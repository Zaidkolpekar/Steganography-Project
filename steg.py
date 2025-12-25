# steg.py
# Core steganography + PBKDF2-based crypto + metadata handling
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import io
import json
import math
import zlib
from typing import Iterable

BLOCK_SIZE = 16
# New header layout includes flags, channel mask and lsb count for robust decoding
# MAGIC(4) | FLAGS(1) | CH_MASK(1) | LSB_COUNT(1) | SALT(16) | ITERS(4 big-endian) | CIPHER_LEN(4 big-endian)
HEADER_MAGIC = b'STEG'    # 4 bytes
SALT_LEN = 16             # bytes
DEFAULT_PBKDF2_ITERS = 200_000

META_SEPARATOR = b'<<<META>>>'

# flag bits
FLAG_COMPRESSED = 0x01

# channel mask constants
CHANNEL_BITS = {'R': 1, 'G': 2, 'B': 4, 'A': 8}
CHANNEL_ORDER = ['R', 'G', 'B', 'A']

def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]

def derive_key_pbkdf2(password: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERS) -> bytes:
    # PBKDF2-HMAC-SHA256 produce 32-byte key
    return PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

def encrypt_with_password(plaintext: bytes, password: str, iterations: int = DEFAULT_PBKDF2_ITERS):
    salt = get_random_bytes(SALT_LEN)
    key = derive_key_pbkdf2(password, salt, iterations)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pad(plaintext))
    return salt, iterations, iv + ct  # return cipher bytes prefixed by IV

def decrypt_with_password(cipher_bytes: bytes, password: str, salt: bytes, iterations: int):
    key = derive_key_pbkdf2(password, salt, iterations)
    iv = cipher_bytes[:16]
    ct = cipher_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return _unpad(pt)

def _to_bitarray(data: bytes) -> list:
    bits = []
    for b in data:
        bits.extend([(b >> i) & 1 for i in reversed(range(8))])
    return bits

def _from_bitarray(bits: list) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)

def channels_to_mask(channels: Iterable[str]) -> int:
    mask = 0
    for ch in channels:
        if ch in CHANNEL_BITS:
            mask |= CHANNEL_BITS[ch]
    return mask

def mask_to_channels(mask: int):
    chs = []
    for ch in CHANNEL_ORDER:
        if mask & CHANNEL_BITS[ch]:
            chs.append(ch)
    return chs

def capacity_in_bits(img: Image.Image, channels=('R','G','B'), lsb_per_channel: int = 1, reserve_header_bytes: int = 256) -> int:
    """
    Return usable capacity in bits for the given image when embedding into selected channels with given LSB count,
    after reserving reserve_header_bytes for header/metadata.
    """
    w, h = img.size
    mode = img.mode  # e.g., 'RGB' or 'RGBA'
    # count available channels present in the image mode
    available = 0
    for ch in channels:
        idx = {'R':0,'G':1,'B':2,'A':3}[ch]
        if idx < len(mode):
            available += 1
    total_pixels = w * h
    total_bits = total_pixels * available * lsb_per_channel
    reserve_bits = reserve_header_bytes * 8
    usable = total_bits - reserve_bits
    if usable < 0:
        usable = 0
    return usable

def _make_header(flags: int, ch_mask: int, lsb_count: int, salt: bytes, iterations: int, cipher_len: int) -> bytes:
    # MAGIC(4) | FLAGS(1) | CH_MASK(1) | LSB_COUNT(1) | SALT(16) | ITERS(4) | CIPHER_LEN(4)
    return HEADER_MAGIC + bytes([flags & 0xFF]) + bytes([ch_mask & 0xFF]) + bytes([lsb_count & 0xFF]) + salt + iterations.to_bytes(4, "big") + cipher_len.to_bytes(4, "big")

def _parse_header(header: bytes):
    # expects at least 4 +1 +1 +1 + SALT_LEN + 8 bytes = 31 bytes
    min_len = 4 + 1 + 1 + 1 + SALT_LEN + 8
    if len(header) < min_len:
        raise ValueError("Header too short.")
    if header[:4] != HEADER_MAGIC:
        raise ValueError("No steg header found.")
    flags = header[4]
    ch_mask = header[5]
    lsb_count = header[6]
    salt = header[7:7+SALT_LEN]
    iters = int.from_bytes(header[7+SALT_LEN:7+SALT_LEN+4], "big")
    cipher_len = int.from_bytes(header[7+SALT_LEN+4:7+SALT_LEN+8], "big")
    return flags, ch_mask, lsb_count, salt, iters, cipher_len

# Public API functions:

def encode_image_bytes_with_metadata(img_bytes: bytes,
                                     payload_bytes: bytes,
                                     filename: str,
                                     mimetype: str = "application/octet-stream",
                                     password: str = None,
                                     pbkdf2_iters: int = DEFAULT_PBKDF2_ITERS,
                                     channels=('R','G','B'),
                                     lsb_per_channel: int = 1,
                                     reserve_header_bytes: int = 256,
                                     compress: bool = False,
                                     progress_callback=None) -> bytes:
    """
    Embed payload_bytes (file or text) into image bytes.
    metadata (filename, mimetype) stored and encrypted along with payload.
    Returns PNG bytes of stego image.

    New optional args:
      - channels: tuple/list of channel letters to use (subset of R,G,B,A)
      - lsb_per_channel: currently only 1 supported
      - reserve_header_bytes: reserved header bytes considered for capacity check
      - compress: whether to compress payload before encryption (zlib)
      - progress_callback(percent_float) optional for UI progress
    """
    if lsb_per_channel != 1:
        raise ValueError("Only lsb_per_channel == 1 supported currently.")

    img = Image.open(io.BytesIO(img_bytes)).convert('RGBA')
    # compute capacity using selected channels
    cap = capacity_in_bits(img, channels=channels, lsb_per_channel=lsb_per_channel, reserve_header_bytes=reserve_header_bytes)

    # prepare plaintext: metadata JSON + separator + payload
    meta = {"filename": filename or "payload.bin", "mimetype": mimetype or "application/octet-stream", "orig_size": len(payload_bytes)}
    meta_bytes = json.dumps(meta).encode('utf-8')
    plaintext = meta_bytes + META_SEPARATOR + payload_bytes

    flags = 0
    # compress plaintext if requested (before encryption)
    if compress:
        plaintext = zlib.compress(plaintext)
        flags |= FLAG_COMPRESSED

    # encrypt or not
    if password:
        salt, iters, cipher_bytes = encrypt_with_password(plaintext, password, iterations=pbkdf2_iters)
    else:
        salt = b'\x00' * SALT_LEN
        iters = 0
        cipher_bytes = plaintext  # unencrypted stored directly

    cipher_len = len(cipher_bytes)
    ch_mask = channels_to_mask(channels)
    header = _make_header(flags, ch_mask, lsb_per_channel, salt, iters, cipher_len)
    full = header + cipher_bytes
    bits = _to_bitarray(full)
    if len(bits) > cap:
        raise ValueError(f"Payload too large for this image. Need {len(bits)} bits, capacity {cap} bits. Use larger image or smaller payload.")

    # embed bits into selected channels (1 LSB per selected channel)
    pixels = list(img.getdata())
    flat = []
    bit_idx = 0
    total_bits = len(bits)
    # determine channel indices we will write in pixel tuples (RGBA)
    channel_indices = []
    for ch in CHANNEL_ORDER:
        if ch in channels:
            # map to RGBA tuple indices
            idx = {'R':0,'G':1,'B':2,'A':3}[ch]
            channel_indices.append(idx)
    # iterate pixels and write
    for pix_idx, px in enumerate(pixels):
        # px is (r,g,b,a)
        pixel = list(px)
        for ci in channel_indices:
            if bit_idx < total_bits:
                pixel[ci] = (pixel[ci] & ~1) | bits[bit_idx]
                bit_idx += 1
        # store as RGB for saving (drop alpha)
        flat.append((pixel[0], pixel[1], pixel[2]))
        # progress callback occasionally
        if progress_callback and (pix_idx % 2048 == 0):
            progress_callback(min(99.0, (bit_idx / total_bits) * 100.0))
    # create new image from flat RGB tuples
    img2 = Image.new('RGB', img.size)
    img2.putdata(flat)
    out = io.BytesIO()
    img2.save(out, format='PNG')
    if progress_callback:
        progress_callback(100.0)
    return out.getvalue()

def decode_image_bytes_with_metadata(stego_img_bytes: bytes, password: str = None, progress_callback=None) -> (bytes, dict):
    """
    Decode and return (payload_bytes, metadata_dict).
    If password is required and incorrect, an exception will be raised.
    """
    img = Image.open(io.BytesIO(stego_img_bytes)).convert('RGBA')
    pixels = list(img.getdata())
    bits = []
    total_pixels = len(pixels)
    for pix_idx, (r, g, b, a) in enumerate(pixels):
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
        bits.append(a & 1)
        if progress_callback and (pix_idx % 2048 == 0):
            progress_callback(min(90.0, (pix_idx / total_pixels) * 100.0))

    # read minimal header first (4 +1 +1 +1 + SALT_LEN + 8) bytes => 31 bytes
    header_bits = bits[: (4 + 1 + 1 + 1 + SALT_LEN + 8) * 8]
    header_bytes = _from_bitarray(header_bits)
    flags, ch_mask, lsb_count, salt, iters, cipher_len = _parse_header(header_bytes)

    # compute where cipher bytes live in the bitstream
    total_bytes_needed = (4 + 1 + 1 + 1 + SALT_LEN + 8) + cipher_len
    total_bits_needed = total_bytes_needed * 8
    if total_bits_needed > len(bits):
        raise ValueError("Image does not contain full payload.")

    cipher_bits = bits[(4 + 1 + 1 + 1 + SALT_LEN + 8) * 8 : total_bits_needed]
    cipher_bytes = _from_bitarray(cipher_bits)

    if iters == 0:
        plaintext = cipher_bytes
    else:
        if not password:
            raise ValueError("Payload is encrypted — password required.")
        plaintext = decrypt_with_password(cipher_bytes, password, salt, iters)

    # if compressed flag is set, decompress
    compressed = bool(flags & FLAG_COMPRESSED)
    if compressed:
        try:
            plaintext = zlib.decompress(plaintext)
        except Exception as e:
            raise ValueError("Payload decompression failed: " + str(e))

    # split metadata and payload
    sep_index = plaintext.find(META_SEPARATOR)
    if sep_index == -1:
        raise ValueError("Malformed payload: metadata separator missing.")
    meta_bytes = plaintext[:sep_index]
    payload_bytes = plaintext[sep_index + len(META_SEPARATOR):]
    try:
        metadata = json.loads(meta_bytes.decode('utf-8'))
    except Exception:
        metadata = {"filename": "payload.bin", "mimetype": "application/octet-stream", "orig_size": len(payload_bytes)}
    if progress_callback:
        progress_callback(100.0)
    return payload_bytes, metadata

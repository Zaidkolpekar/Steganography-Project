# utils.py
from PIL import Image
from typing import Iterable, Tuple

# channel masks / indices and ordering
CHANNEL_INDEX = {'R': 0, 'G': 1, 'B': 2, 'A': 3}
CHANNEL_BITS = {'R': 1, 'G': 2, 'B': 4, 'A': 8}
CHANNEL_ORDER = ['R', 'G', 'B', 'A']

def channels_to_mask(channels: Iterable[str]) -> int:
    """Convert iterable of channel letters into a bitmask integer."""
    mask = 0
    for ch in channels:
        if ch not in CHANNEL_BITS:
            raise ValueError(f'Unknown channel: {ch}')
        mask |= CHANNEL_BITS[ch]
    return mask

def mask_to_channels(mask: int) -> Tuple[str, ...]:
    """Return tuple of channel letters enabled in mask."""
    chs = []
    for ch in CHANNEL_ORDER:
        if mask & CHANNEL_BITS[ch]:
            chs.append(ch)
    return tuple(chs)

def exact_capacity_bits(image: Image.Image,
                        channels: Iterable[str] = ('R', 'G', 'B'),
                        lsb_per_channel: int = 1,
                        reserve_header_bytes: int = 256) -> Tuple[int, int]:
    """
    Return (usable_bits, usable_bytes) available for payload after reserving header.

    - channels: iterable of 'R','G','B','A'
    - lsb_per_channel: how many LSBs per selected channel (int >=1)
    - reserve_header_bytes: header bytes reserved (default 256)
    """
    if lsb_per_channel < 1:
        raise ValueError('lsb_per_channel must be >= 1')

    w, h = image.size
    mode = image.mode  # e.g., 'RGB', 'RGBA', 'L', etc.

    # count actual selectable channels present in the image mode
    available_channels = 0
    for ch in channels:
        idx = CHANNEL_INDEX.get(ch)
        # For modes like 'RGB' (len=3), indices 0..2 are valid
        if idx is not None and idx < len(mode):
            available_channels += 1

    total_pixels = w * h
    total_bits = total_pixels * available_channels * lsb_per_channel
    reserve_bits = reserve_header_bytes * 8
    usable_bits = total_bits - reserve_bits
    if usable_bits < 0:
        usable_bits = 0
    usable_bytes = usable_bits // 8
    return usable_bits, usable_bytes

def capacity_report(image: Image.Image,
                    channels: Iterable[str] = ('R', 'G', 'B'),
                    lsb_per_channel: int = 1,
                    reserve_header_bytes: int = 256) -> str:
    """Human-readable capacity report for UI."""
    bits, bytes_ = exact_capacity_bits(image, channels, lsb_per_channel, reserve_header_bytes)
    w, h = image.size
    channels_list = tuple(channels)
    return (f'Image: {w}×{h} ({w*h} px)\n'
            f'Channels used: {channels_list} | LSBs per channel: {lsb_per_channel}\n'
            f'Usable capacity (after reserving {reserve_header_bytes} bytes for header): {bytes_} bytes ({bits} bits)')

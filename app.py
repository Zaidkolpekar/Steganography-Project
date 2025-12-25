# app.py

import streamlit as st
from PIL import Image
import io
import mimetypes
import json
import math
import zlib
from steg import encode_image_bytes_with_metadata, decode_image_bytes_with_metadata, capacity_in_bits, FLAG_COMPRESSED

# lottie animation
from streamlit_lottie import st_lottie
import requests

# -------------------------
# Helper: load lottie JSON
# -------------------------
def load_lottieurl(url: str):
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

# -------------------------
# Page config & small CSS
# -------------------------
st.set_page_config(page_title="StegoPro — Image Steganography", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(180deg, #071326 0%, #041622 100%); color: #e6eef8; font-family: "Segoe UI", Roboto, Arial, sans-serif; }
    .card { background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); padding: 18px; border-radius: 12px; box-shadow: 0 6px 18px rgba(2,6,23,0.6); border: 1px solid rgba(255,255,255,0.02); }
    .muted { color: #a8b3c7; }
    .big-title { font-size: 28px; font-weight:700; margin:0; color: #fff; }
    .sub { color: #cfe3ff; margin-top:4px; margin-bottom:8px; }
    .small { font-size:13px; color:#bfcfe6; }
    .stButton>button { background-color:#0ea5a0; color: white; border-radius:8px; padding:8px 14px; }
    .stDownloadButton>button { background-color:#06b6d4; color:white; border-radius:8px; padding:8px 14px; }
    .info-box { background: rgba(255,255,255,0.02); padding:10px; border-radius:8px; border:1px solid rgba(255,255,255,0.02); }
    .muted-small { color:#94a6bc; font-size:13px; margin-top:4px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------
# Header with Lottie
# -------------------------
lottie_url = "https://assets6.lottiefiles.com/packages/lf20_jcikwtux.json"
lottie_json = load_lottieurl(lottie_url)

header_col1, header_col2 = st.columns([3,1])
with header_col1:
    st.markdown('<div style="padding:8px 0;"><h1 style="margin:0; color:#fff;">StegoPro</h1><div style="color:#cfe3ff;">Secure image steganography — LSB + AES (PBKDF2)</div><div class="muted-small">Embed files or text into PNG images. Optionally encrypt payload with a password.</div></div>', unsafe_allow_html=True)
with header_col2:
    if lottie_json:
        st_lottie(lottie_json, height=140)
    else:
        st.image(None)

st.markdown("<br/>", unsafe_allow_html=True)

# -------------------------
# Main layout: big column + side
# -------------------------
col_main, col_side = st.columns([3,1])

with col_main:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    mode = st.radio("", ["Encode (Hide File/Text)", "Decode (Extract)"], horizontal=True)

    if mode == "Encode (Hide File/Text)":
        st.header("Encode — embed a file or text")
        st.markdown("<div class='muted-small'>Upload a PNG cover and a file or text. Encrypt payload with a password (optional).</div>", unsafe_allow_html=True)

        cover = st.file_uploader("Cover image (PNG recommended)", type=["png","jpg","jpeg"], key="cover_enc")
        col1, col2 = st.columns([2,1])
        with col1:
            text = st.text_area("Text to embed (leave empty if embedding a file)", height=120)
        with col2:
            file_to_hide = st.file_uploader("Or choose a file to hide", type=None, key="file_enc")
        password = st.text_input("Password (optional — encrypt payload)", type="password", key="pw_enc")
        iters = st.number_input("PBKDF2 iterations", min_value=1000, max_value=5000000, value=200000, step=1000, help="Higher means stronger but slower")

        # --- NEW: capacity controls (channels + reserve header) ---
        st.markdown("<hr style='border:1px solid rgba(255,255,255,0.03)'/>", unsafe_allow_html=True)
        st.markdown("<div class='muted-small'>Capacity settings (added)</div>", unsafe_allow_html=True)
        channels = st.multiselect('Channels to use', options=['R','G','B','A'], default=['R','G','B'])
        # currently embedder supports 1 LSB per selected channel - keep UI limited to 1 for now
        lsb_per_channel = 1
        reserve_bytes = st.number_input('Reserve header bytes (safety)', min_value=42, max_value=65535, value=256, step=1)

        # --- NEW: compression option ---
        st.markdown("<div class='muted-small'>Optional enhancements</div>", unsafe_allow_html=True)
        compress_toggle = st.checkbox("Compress payload (zlib) before encryption", value=False)
        st.markdown("<br/>", unsafe_allow_html=True)

        cover_bytes = None
        cap_bits = 0
        if cover:
            try:
                cover_bytes = cover.read()
                img_preview = Image.open(io.BytesIO(cover_bytes))
                st.image(img_preview, caption="Cover preview", use_column_width=True)
                # compute usable capacity in bits using user-selected channels/lsb/reserve
                cap_bits = capacity_in_bits(img_preview, channels=channels, lsb_per_channel=lsb_per_channel, reserve_header_bytes=reserve_bytes)
                cap_bytes = cap_bits // 8
                st.markdown(f"<div class='small muted'>Image usable capacity: <b>{cap_bytes}</b> bytes ({cap_bits} bits) — using {lsb_per_channel} LSB per {','.join(channels)} channel(s) with {reserve_bytes} bytes reserved for header</div>", unsafe_allow_html=True)
            except Exception:
                st.error("Uploaded cover is not a valid image.")
                cover_bytes = None

        st.markdown("<br/>", unsafe_allow_html=True)
        if st.button("Encode & Download Stego PNG"):
            if not cover_bytes:
                st.error("Please upload a valid cover image.")
            elif not text and not file_to_hide:
                st.error("Provide text or a file to embed.")
            else:
                if file_to_hide:
                    payload = file_to_hide.read()
                    filename = file_to_hide.name
                    mimetype = getattr(file_to_hide, "type", None) or mimetypes.guess_type(filename)[0] or "application/octet-stream"
                else:
                    payload = text.encode("utf-8")
                    filename = "message.txt"
                    mimetype = "text/plain"
                try:
                    # Better estimate: compute expected cipher length before committing
                    # Build plaintext bytes (meta + separator + payload), but if compress_toggle is set, compress it
                    meta = {"filename": filename or "payload.bin", "mimetype": mimetype or "application/octet-stream", "orig_size": len(payload)}
                    meta_bytes = json.dumps(meta).encode("utf-8")
                    plaintext = meta_bytes + b'<<<META>>>' + payload
                    if compress_toggle:
                        compressed_plaintext = zlib.compress(plaintext)
                        est_plaintext_len = len(compressed_plaintext)
                        est_compressed = True
                    else:
                        est_plaintext_len = len(plaintext)
                        est_compressed = False

                    if password:
                        # ciphertext will be IV(16) + padded ciphertext (padded to 16)
                        padded_len = math.ceil(est_plaintext_len / 16) * 16
                        est_cipher_len = 16 + padded_len
                    else:
                        est_cipher_len = est_plaintext_len

                    # header size in our steg.py: 4 + FLAGS(1) + CH_MASK(1) + LSB(1) + SALT_LEN(16) + 4 + 4
                    est_header_len = 4 + 1 + 1 + 1 + 16 + 4 + 4  # 31 bytes
                    est_total_bytes = est_header_len + est_cipher_len
                    est_bits_needed = est_total_bytes * 8

                    if cap_bits and est_bits_needed > cap_bits:
                        st.error("Payload likely too large for this image with the chosen options. Use a larger image or change settings.")
                        st.info(f"Estimated need: {est_total_bytes} bytes; usable: {cap_bits//8} bytes.")
                    else:
                        # progress UI
                        progress_bar = st.progress(0)
                        status = st.empty()
                        def progress_cb(pct):
                            try:
                                progress_bar.progress(int(pct))
                                status.text(f'Encoding: {pct:.1f}%')
                            except Exception:
                                pass

                        # call updated steg function (pass channels/reserve and compress flag)
                        stego_png = encode_image_bytes_with_metadata(cover_bytes, payload, filename, mimetype, password or None, int(iters),
                                                                    channels=channels, lsb_per_channel=lsb_per_channel, reserve_header_bytes=reserve_bytes,
                                                                    compress=compress_toggle, progress_callback=progress_cb)
                        st.success("Embedding successful. Download your stego PNG below.")
                        st.download_button("Download Stego Image", data=stego_png, file_name="stego.png", mime="image/png")
                except Exception as e:
                    st.error(f"Embedding failed: {e}")

    else:
        st.header("Decode — extract payload from stego PNG")
        st.markdown("<div class='muted-small'>Upload the stego PNG file you received. If encrypted, enter the password used during encoding.</div>", unsafe_allow_html=True)
        stego_file = st.file_uploader("Stego image (PNG)", type=["png","jpg","jpeg"], key="stego_dec")
        password_dec = st.text_input("Password (if used)", type="password", key="pw_dec_ui")

        if st.button("Decode"):
            if not stego_file:
                st.error("Please upload a stego image.")
            else:
                stego_bytes = stego_file.read()
                try:
                    progress_bar = st.progress(0)
                    status = st.empty()
                    def progress_cb(pct):
                        try:
                            progress_bar.progress(int(pct))
                            status.text(f'Decoding: {pct:.1f}%')
                        except Exception:
                            pass

                    payload_bytes, metadata = decode_image_bytes_with_metadata(stego_bytes, password_dec or None, progress_callback=progress_cb)
                    st.success("Decoded successfully.")
                    st.markdown("<div class='info-box'>", unsafe_allow_html=True)
                    st.write("**Filename:**", metadata.get("filename"))
                    st.write("**MIME type:**", metadata.get("mimetype"))
                    st.write("**Original size (bytes):**", metadata.get("orig_size"))
                    st.markdown("</div>", unsafe_allow_html=True)

                    try:
                        txt = payload_bytes.decode("utf-8")
                        st.text_area("Decoded Text", value=txt, height=200)
                        st.download_button("Download as TXT", data=payload_bytes, file_name=metadata.get("filename", "decoded.txt"), mime="text/plain")
                    except Exception:
                        st.write(f"Binary payload ({len(payload_bytes)} bytes).")
                        st.download_button("Download file", data=payload_bytes, file_name=metadata.get("filename", "payload.bin"), mime=metadata.get("mimetype", "application/octet-stream"))
                except Exception as e:
                    st.error(f"Decoding failed: {e}")

    st.markdown('</div>', unsafe_allow_html=True)

with col_side:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("About StegoPro")
    st.markdown(
        """
        **StegoPro** is an academic tool demonstrating secure LSB steganography.
        - LSB: hides bits in least-significant bits of pixels.
        - Encryption: PBKDF2-HMAC-SHA256 + AES-CBC (password optional).
        - Metadata: filename and MIME type saved inside payload.
        """,
        unsafe_allow_html=True,
    )
    st.markdown("---")
    st.subheader("Quick Tips")
    st.markdown(
        """
        - Use **PNG** and send as **File/Document** (not as image preview).  
        - For quick tests, set PBKDF2 iterations lower (e.g. 10000).  
        - Always share the password via a separate secure channel.
        """,
        unsafe_allow_html=True,
    )
    st.markdown("---")
    st.subheader("Demo")
    if st.button("Run encode→decode demo (sample)"):
        try:
            from PIL import Image as PILImage
            img = PILImage.new("RGB", (300,200), (70,120,180))
            buf = io.BytesIO(); img.save(buf, "PNG"); cover_bytes = buf.getvalue()
            payload = b"Demo message from StegoPro"
            # default channels will be RGB, no compression
            stego = encode_image_bytes_with_metadata(cover_bytes, payload, "demo.txt", "text/plain", password=None, pbkdf2_iters=10000)
            payload_out, meta = decode_image_bytes_with_metadata(stego, password=None)
            st.success("Demo completed — see results below.")
            st.write("Decoded:", payload_out.decode("utf-8"))
            st.write("Meta:", meta)
            st.download_button("Download demo stego.png", data=stego, file_name="stego_demo.png", mime="image/png")
        except Exception as e:
            st.error("Demo failed: " + str(e))
    st.markdown("</div>", unsafe_allow_html=True)


st.markdown('<div style="text-align:center; color:#97aabd;">Made by Zaid — MSc Cybersecurity project</div>', unsafe_allow_html=True)

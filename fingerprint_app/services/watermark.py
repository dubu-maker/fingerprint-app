import base64
import hmac
import hashlib
import os
import random
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import cv2
import numpy as np
from flask import current_app

from ..extensions import db
from ..models import Image, User

PREFIX_SALT_BYTES = 16
PREFIX_LENGTH_BITS = 16
PREFIX_TOTAL_BITS = PREFIX_SALT_BYTES * 8 + PREFIX_LENGTH_BITS


def _bitstring_from_bytes(data: bytes) -> list[int]:
    return [int(bit) for bit in ''.join(f'{byte:08b}' for byte in data)]


def _bytes_from_bits(bits: list[int]) -> bytes:
    return bytes(
        int(''.join(str(bit) for bit in bits[i:i + 8]), 2)
        for i in range(0, len(bits), 8)
    )


def _get_block_coordinates(height: int, width: int):
    h_aligned = height - (height % 8)
    w_aligned = width - (width % 8)
    coords = [(y, x) for y in range(0, h_aligned, 8) for x in range(0, w_aligned, 8)]
    return coords, h_aligned, w_aligned


def _embed_bit_in_block(block: np.ndarray, bit: int, delta: float) -> np.ndarray:
    dct = cv2.dct(block)
    c_a = dct[2, 3]
    c_b = dct[3, 2]
    if bit == 1:
        if c_a <= c_b + delta:
            c_a = c_b + delta
    else:
        if c_b <= c_a + delta:
            c_b = c_a + delta
    dct[2, 3] = c_a
    dct[3, 2] = c_b
    block_mod = cv2.idct(dct)
    return np.clip(block_mod, 0, 255)


def _extract_bit_from_block(block: np.ndarray) -> int:
    dct = cv2.dct(block)
    return 1 if dct[2, 3] > dct[3, 2] else 0


def _apply_bit_map_to_plane(plane: np.ndarray, coords, bit_map: dict[int, int], delta: float) -> np.ndarray:
    if not bit_map:
        return plane
    region = plane.astype(np.float32)
    applied = 0
    for idx, (y, x) in enumerate(coords):
        bit = bit_map.get(idx)
        if bit is None:
            continue
        block = region[y:y + 8, x:x + 8]
        region[y:y + 8, x:x + 8] = _embed_bit_in_block(block, bit, delta)
        applied += 1
    if applied != len(bit_map):
        raise ValueError('워터마크를 삽입하기 위한 공간이 부족합니다.')
    return np.clip(region, 0, 255).astype(np.uint8)


def _build_bit_map(total_blocks: int, payload: bytes, secret: bytes):
    salt = secrets.token_bytes(PREFIX_SALT_BYTES)
    prefix_bits = _bitstring_from_bytes(salt) + [int(bit) for bit in f'{len(payload):016b}']
    data_bits = _bitstring_from_bytes(payload)
    total_bits = len(prefix_bits) + len(data_bits)
    if total_bits > total_blocks:
        raise ValueError('미디어가 핑거프린트를 담기에 충분히 크지 않습니다.')
    bit_map = {idx: bit for idx, bit in enumerate(prefix_bits)}
    available_indices = list(range(len(prefix_bits), total_blocks))
    rng_seed = int.from_bytes(hmac.new(secret, salt, hashlib.sha256).digest()[:8], 'big')
    rng = random.Random(rng_seed)
    rng.shuffle(available_indices)
    data_indices = available_indices[:len(data_bits)]
    for idx, bit in zip(data_indices, data_bits):
        bit_map[idx] = bit
    return bit_map, salt, len(payload)


def _decode_prefix(prefix_bits: list[int]):
    if len(prefix_bits) < PREFIX_TOTAL_BITS:
        return None, None
    salt_bits = prefix_bits[:PREFIX_SALT_BYTES * 8]
    length_bits = prefix_bits[PREFIX_SALT_BYTES * 8:PREFIX_TOTAL_BITS]
    salt_bytes = _bytes_from_bits(salt_bits)
    payload_length = int(''.join(str(bit) for bit in length_bits), 2)
    return salt_bytes, payload_length


def _decode_payload(prefix_bits: list[int], extra_bits: dict[int, int], total_blocks: int, secret: bytes):
    salt_bytes, payload_length = _decode_prefix(prefix_bits)
    if salt_bytes is None or payload_length is None:
        return None
    data_bits_needed = payload_length * 8
    if data_bits_needed == 0:
        return ''
    available_indices = list(range(PREFIX_TOTAL_BITS, total_blocks))
    if len(available_indices) < data_bits_needed:
        return None
    rng_seed = int.from_bytes(hmac.new(secret, salt_bytes, hashlib.sha256).digest()[:8], 'big')
    rng = random.Random(rng_seed)
    rng.shuffle(available_indices)
    data_indices = available_indices[:data_bits_needed]
    bits = []
    for idx in data_indices:
        bit = extra_bits.get(idx)
        if bit is None:
            return None
        bits.append(bit)
    data_bytes = _bytes_from_bits(bits)
    try:
        return data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _run_ffmpeg(args: list[str]) -> bool:
    ffmpeg_bin = current_app.config['FFMPEG_BIN']
    if not shutil.which(ffmpeg_bin):
        return False
    try:
        subprocess.run([ffmpeg_bin, *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        current_app.logger.warning("FFmpeg 실행 오류: %s", exc)
        return False


def embed_image(image_path: str, payload: str, secret: bytes, delta: float) -> str:
    payload_bytes = payload.encode('utf-8')
    frame = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if frame is None:
        raise ValueError('이미지를 읽을 수 없습니다.')
    coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
    total_blocks = len(coords)
    bit_map, _, _ = _build_bit_map(total_blocks, payload_bytes, secret)
    ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)
    region = y[:h_aligned, :w_aligned]
    region_modified = _apply_bit_map_to_plane(region, coords, bit_map, delta)
    y[:h_aligned, :w_aligned] = region_modified
    processed = cv2.merge([y, cr, cb])
    result = cv2.cvtColor(processed, cv2.COLOR_YCrCb2BGR)
    base, ext = os.path.splitext(image_path)
    output_path = f"{base}_fp{ext}"
    if not cv2.imwrite(output_path, result):
        raise ValueError('워터마크된 이미지를 저장할 수 없습니다.')
    return output_path


def extract_image(image_path: str, secret: bytes):
    frame = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if frame is None:
        return None
    coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
    if not coords:
        return None
    ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
    y = ycrcb[:, :, 0]
    plane = y[:h_aligned, :w_aligned].astype(np.float32)
    prefix_bits = []
    extra_bits = {}
    for idx, (y_off, x_off) in enumerate(coords):
        block = plane[y_off:y_off + 8, x_off:x_off + 8]
        bit = _extract_bit_from_block(block)
        if idx < PREFIX_TOTAL_BITS:
            prefix_bits.append(bit)
        else:
            extra_bits[idx] = bit
    return _decode_payload(prefix_bits, extra_bits, len(coords), secret)


def embed_video(video_path: str, payload: str, secret: bytes, delta: float) -> str:
    payload_bytes = payload.encode('utf-8')
    ext = Path(video_path).suffix
    audio_temp_path = None
    temp_video_output = None

    tmp_audio = tempfile.NamedTemporaryFile(suffix='.aac', delete=False)
    tmp_audio.close()
    if _run_ffmpeg(['-y', '-i', video_path, '-vn', '-acodec', 'copy', tmp_audio.name]):
        audio_temp_path = tmp_audio.name
    else:
        os.unlink(tmp_audio.name)

    capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        raise ValueError('동영상을 읽을 수 없습니다.')
    frame_block_counts = []
    success, frame = capture.read()
    while success:
        coords, _, _ = _get_block_coordinates(frame.shape[0], frame.shape[1])
        frame_block_counts.append(len(coords))
        success, frame = capture.read()
    capture.release()
    total_blocks = sum(frame_block_counts)
    if total_blocks == 0:
        raise ValueError('동영상 프레임이 너무 작습니다.')
    bit_map, _, _ = _build_bit_map(total_blocks, payload_bytes, secret)
    capture = cv2.VideoCapture(video_path)
    fps = capture.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    temp_video_output = f"{os.path.splitext(video_path)[0]}_fp_video{ext}"
    final_output = f"{os.path.splitext(video_path)[0]}_fp{ext}"
    writer = cv2.VideoWriter(temp_video_output, fourcc, fps, (width, height))
    if not writer.isOpened():
        capture.release()
        raise ValueError('워터마크된 동영상을 저장할 수 없습니다.')

    global_index = 0
    applied_indices = set()
    for count in frame_block_counts:
        success, frame = capture.read()
        if not success:
            break
        coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
        ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
        y, cr, cb = cv2.split(ycrcb)
        region = y[:h_aligned, :w_aligned]
        frame_map = {}
        for local_idx in range(len(coords)):
            global_idx = global_index + local_idx
            bit = bit_map.get(global_idx)
            if bit is not None:
                frame_map[local_idx] = bit
                applied_indices.add(global_idx)
        if frame_map:
            region_modified = _apply_bit_map_to_plane(region, coords, frame_map, delta)
            y[:h_aligned, :w_aligned] = region_modified
        merged = cv2.merge([y, cr, cb])
        writer.write(cv2.cvtColor(merged, cv2.COLOR_YCrCb2BGR))
        global_index += len(coords)
    capture.release()
    writer.release()

    if len(applied_indices) != len(bit_map):
        raise ValueError('워터마크를 삽입하기 위한 동영상 길이가 충분하지 않습니다.')

    try:
        if audio_temp_path and _run_ffmpeg(['-y', '-i', temp_video_output, '-i', audio_temp_path, '-c', 'copy', final_output]):
            os.remove(temp_video_output)
        else:
            os.replace(temp_video_output, final_output)
    finally:
        if audio_temp_path and os.path.exists(audio_temp_path):
            os.remove(audio_temp_path)
        if os.path.exists(temp_video_output) and temp_video_output != final_output:
            try:
                os.remove(temp_video_output)
            except OSError:
                pass

    return final_output


def extract_video(video_path: str, secret: bytes):
    capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        return None
    prefix_bits = []
    extra_bits = {}
    global_index = 0
    while True:
        success, frame = capture.read()
        if not success:
            break
        coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
        if not coords:
            continue
        ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
        y = ycrcb[:, :, 0]
        plane = y[:h_aligned, :w_aligned].astype(np.float32)
        for local_idx, (y_off, x_off) in enumerate(coords):
            global_idx = global_index + local_idx
            block = plane[y_off:y_off + 8, x_off:x_off + 8]
            bit = _extract_bit_from_block(block)
            if global_idx < PREFIX_TOTAL_BITS:
                prefix_bits.append(bit)
            else:
                extra_bits[global_idx] = bit
        global_index += len(coords)
    capture.release()
    if global_index == 0:
        return None
    return _decode_payload(prefix_bits, extra_bits, global_index, secret)


def embed_media(media_path: str, payload: str) -> str:
    secret = current_app.config['FINGERPRINT_SECRET'].encode('utf-8')
    delta = current_app.config['WATERMARK_DCT_DELTA']
    ext = Path(media_path).suffix.lower().lstrip('.')
    image_exts = current_app.config['IMAGE_EXTENSIONS']
    video_exts = current_app.config['VIDEO_EXTENSIONS']
    if ext in image_exts:
        return embed_image(media_path, payload, secret, delta)
    if ext in video_exts:
        return embed_video(media_path, payload, secret, delta)
    raise ValueError('지원되지 않는 파일 형식입니다.')


def extract_media(media_path: str):
    secret = current_app.config['FINGERPRINT_SECRET'].encode('utf-8')
    ext = Path(media_path).suffix.lower().lstrip('.')
    image_exts = current_app.config['IMAGE_EXTENSIONS']
    video_exts = current_app.config['VIDEO_EXTENSIONS']
    if ext in image_exts:
        return extract_image(media_path, secret)
    if ext in video_exts:
        return extract_video(media_path, secret)
    return None


def process_watermark_job(user_id: int, username: str, original_filename: str, original_path: str, token: str):
    app = current_app._get_current_object() if current_app else None
    if app is None:
        from .. import create_app
        app = create_app()

    with app.app_context():
        fingerprinted_path = embed_media(original_path, token)
        fingerprinted_filename = os.path.basename(fingerprinted_path)
        record = Image(filename=fingerprinted_filename,
                       fingerprint_text=token,
                       user_id=user_id)
        db.session.add(record)
        db.session.commit()
        app.logger.info("[QUEUE] %s 파일 처리 완료: %s", username, fingerprinted_filename)
        return fingerprinted_filename

def generate_token(username: str) -> str:
    secret = current_app.config['FINGERPRINT_SECRET'].encode('utf-8')
    nonce = secrets.token_bytes(8)
    timestamp = int(datetime.utcnow().timestamp())
    timestamp_bytes = timestamp.to_bytes(8, 'big')
    signature = hmac.new(secret, nonce + timestamp_bytes + username.encode('utf-8'), hashlib.sha256).digest()
    payload = nonce + timestamp_bytes + signature
    return base64.urlsafe_b64encode(payload).decode('utf-8')


def resolve_owner(token: str):
    secret = current_app.config['FINGERPRINT_SECRET'].encode('utf-8')
    try:
        raw = base64.urlsafe_b64decode(token.encode('utf-8'))
        if len(raw) != 48:
            return None, None
        nonce = raw[:8]
        timestamp_bytes = raw[8:16]
        signature = raw[16:]
    except Exception as exc:
        current_app.logger.warning("토큰 해석 실패: %s", exc)
        return None, None

    for user in User.query.all():
        expected = hmac.new(secret, nonce + timestamp_bytes + user.username.encode('utf-8'), hashlib.sha256).digest()
        if hmac.compare_digest(signature, expected):
            timestamp = int.from_bytes(timestamp_bytes, 'big')
            issued_at = datetime.fromtimestamp(timestamp)
            return user.username, issued_at
    return None, None

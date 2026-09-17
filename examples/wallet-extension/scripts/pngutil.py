"""Minimal PNG reader/writer and downscaler (stdlib only)."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _crc(chunk_type: bytes, data: bytes) -> int:
    return zlib.crc32(chunk_type + data) & 0xFFFFFFFF


def read_png(path: Path) -> tuple[int, int, list[int]]:
    data = path.read_bytes()
    if data[:8] != _PNG_SIG:
        raise ValueError(f"{path} is not a PNG")

    width = height = bit_depth = color_type = None
    idat = bytearray()
    offset = 8
    while offset + 8 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk[:10])
        elif chunk_type == b"IDAT":
            idat.extend(chunk)
        elif chunk_type == b"IEND":
            break

    if width is None or height is None or bit_depth is None or color_type is None:
        raise ValueError(f"{path} is missing IHDR")
    if bit_depth != 8 or color_type not in (2, 6):
        raise ValueError(f"{path} must be 8-bit RGB or RGBA")

    raw = zlib.decompress(bytes(idat))
    channels = 3 if color_type == 2 else 4
    stride = width * channels
    pixels = [0] * (width * height * 4)
    src = 0
    prev = bytearray(stride)
    for y in range(height):
        filter_type = raw[src]
        src += 1
        row = bytearray(raw[src : src + stride])
        src += stride
        if filter_type == 1:
            for i in range(stride):
                left = row[i - channels] if i >= channels else 0
                row[i] = (row[i] + left) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = row[i - channels] if i >= channels else 0
                row[i] = (row[i] + ((left + prev[i]) // 2)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                left = row[i - channels] if i >= channels else 0
                up = prev[i]
                up_left = prev[i - channels] if i >= channels else 0
                p = left + up - up_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
                pred = left if pa <= pb and pa <= pc else up if pb <= pc else up_left
                row[i] = (row[i] + pred) & 0xFF
        elif filter_type != 0:
            raise ValueError(f"unsupported PNG filter {filter_type}")

        dst = y * width * 4
        if channels == 4:
            pixels[dst : dst + stride] = row
        else:
            for x in range(width):
                i = x * 3
                o = dst + x * 4
                pixels[o : o + 4] = (row[i], row[i + 1], row[i + 2], 255)
        prev = row

    return width, height, pixels


def write_png(path: Path, width: int, height: int, pixels: list[int]) -> None:
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)
        start = y * stride
        raw.extend(pixels[start : start + stride])

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", _crc(tag, payload))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    path.write_bytes(
        _PNG_SIG
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def resize(pixels: list[int], src_w: int, src_h: int, dst_w: int, dst_h: int) -> list[int]:
    out = [0] * (dst_w * dst_h * 4)
    for y in range(dst_h):
        y0 = y * src_h // dst_h
        y1 = max(y0 + 1, (y + 1) * src_h // dst_h)
        for x in range(dst_w):
            x0 = x * src_w // dst_w
            x1 = max(x0 + 1, (x + 1) * src_w // dst_w)
            r = g = b = a = count = 0
            for sy in range(y0, y1):
                row = sy * src_w * 4
                for sx in range(x0, x1):
                    i = row + sx * 4
                    r += pixels[i]
                    g += pixels[i + 1]
                    b += pixels[i + 2]
                    a += pixels[i + 3]
                    count += 1
            o = (y * dst_w + x) * 4
            out[o : o + 4] = (r // count, g // count, b // count, a // count)
    return out


def place(dst: list[int], dst_w: int, dst_h: int, src: list[int], src_w: int, src_h: int, x: int, y: int) -> None:
    for row in range(src_h):
        dy = y + row
        if dy < 0 or dy >= dst_h:
            continue
        for col in range(src_w):
            dx = x + col
            if dx < 0 or dx >= dst_w:
                continue
            si = (row * src_w + col) * 4
            di = (dy * dst_w + dx) * 4
            src_a = src[si + 3]
            if src_a == 0:
                continue
            if src_a == 255:
                dst[di : di + 4] = src[si : si + 4]
                continue
            inv = 255 - src_a
            dst[di] = (src[si] * src_a + dst[di] * inv) // 255
            dst[di + 1] = (src[si + 1] * src_a + dst[di + 1] * inv) // 255
            dst[di + 2] = (src[si + 2] * src_a + dst[di + 2] * inv) // 255
            dst[di + 3] = min(255, src_a + (dst[di + 3] * inv) // 255)

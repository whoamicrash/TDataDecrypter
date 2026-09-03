import gzip
import json
import struct
import zlib

from .constants import GOOD_BOXES


def sniff_media(data: bytes, deep: bool = False):
    def at(off):
        if data[off:off + 3] == b'\xff\xd8\xff':
            return ('jpg', off)
        if data[off:off + 8] == b'\x89PNG\r\n\x1a\n':
            return ('png', off)
        if data[off:off + 6] in (b'GIF87a', b'GIF89a'):
            return ('gif', off)
        if data[off:off + 4] == b'OggS':
            return ('ogg', off)
        if data[off:off + 4] == b'\x1aE\xdf\xa3':
            return ('webm', off)
        if data[off:off + 3] == b'ID3' or (len(data) > off + 2 and data[off] == 0xFF and data[off + 1] in (0xFB, 0xF3, 0xF2)):
            return ('mp3', off)
        if data[off:off + 4] == b'%PDF':
            return ('pdf', off)
        if data[off:off + 4] == b'RIFF' and data[off + 8:off + 12] == b'WEBP':
            return ('webp', off)
        if data[off:off + 4] == b'RIFF' and data[off + 8:off + 12] == b'WAVE':
            return ('wav', off)
        if data[off + 4:off + 8] == b'ftyp':
            brand = data[off + 8:off + 12]
            if brand in (b'avif', b'avis'):
                return ('avif', off)
            if brand == b'qt  ':
                return ('mov', off)
            return ('mp4', off)
        if data[off:off + 3] == b'\x1f\x8b\x08':
            return ('tgs', off)
        if data[off:off + 16] == b'SQLite format 3\x00':
            return ('sqlite', off)
        if data[off:off + 4] == b'<svg' or (
                data[off:off + 5] == b'<?xml' and b'<svg' in data[off:off + 512]):
            return ('svg', off)
        return (None, off)

    ext, off = at(0)
    if ext:
        return ext, 0
    if deep:
        try:
            for sig in (b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'OggS',
                        b'GIF87a', b'GIF89a', b'%PDF'):
                pos = data.find(sig)
                if pos > 0:
                    ext2, off2 = at(pos)
                    if ext2:
                        return ext2, pos
        except Exception:
            return None, 0
    return None, 0


def trim_jpeg(d):
    if d[:3] != b'\xff\xd8\xff':
        return None
    i = d.rfind(b'\xff\xd9')
    if i >= 0:
        return d[:i + 2]
    return None


def jpeg_sane(d, limit_segments=48) -> bool:
    if len(d) < 8 or d[:3] != b'\xff\xd8\xff':
        return False
    i, saw_sof, saw_dqt, saw_sos = 2, False, False, False
    for _ in range(limit_segments):
        if i + 2 > len(d):
            break
        if d[i] != 0xFF:
            return False
        m = d[i + 1]
        if m in (0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xD9:
            break
        if m == 0xDA:
            saw_sos = True
            break
        if i + 4 > len(d):
            return False
        ln = struct.unpack('>H', d[i + 2:i + 4])[0]
        if ln < 2 or i + 2 + ln > len(d):
            return False
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            saw_sof = True
        if m == 0xDB:
            saw_dqt = True
        i += 2 + ln
    return saw_sof and (saw_sos or saw_dqt)


def first_gzip_member(d):
    if d[:3] != b'\x1f\x8b\x08':
        return None
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        dec.decompress(d)
        dec.flush()
        end = len(d) - len(dec.unused_data)
        return d[:end] if end else None
    except Exception:
        return None


def val_tgs(d):
    t = first_gzip_member(d)
    if not t:
        return None
    try:
        j = json.loads(gzip.decompress(t))
        if isinstance(j, dict) and ('layers' in j or 'body' in j
                                    or ('fr' in j and 'op' in j)):
            return t
    except Exception:
        pass
    return None


def val_webp(d):
    return d[:4] == b'RIFF' and d[8:12] == b'WEBP' and d[12:16] in (b'VP8 ', b'VP8L', b'VP8X')


def val_webm(d):
    return d[:4] == b'\x1aE\xdf\xa3'


def val_ogg(d):
    if d[:4] != b'OggS':
        return False
    return b'OpusHead' in d[:512] or d.count(b'OggS') >= 2


def mp4_walk(d):
    pos = 0
    n = len(d)
    boxes = []
    while pos + 8 <= n:
        size = struct.unpack('>I', d[pos:pos + 4])[0]
        typ = d[pos + 4:pos + 8]
        if size == 1:
            if pos + 16 > n:
                return boxes, pos, False
            size = struct.unpack('>Q', d[pos + 8:pos + 16])[0]
            if size < 16:
                return boxes, pos, False
        elif size < 8:
            return boxes, pos, False
        if typ not in GOOD_BOXES:
            return boxes, pos, False
        boxes.append((pos, size, typ))
        if pos + size > n:
            return boxes, pos + size, False
        pos += size
    return boxes, pos, pos == n


def val_mp4(d):
    boxes, end, ok = mp4_walk(d)
    if not boxes or b'moov' not in [t for _, _, t in boxes]:
        return False, 'no-moov', d
    if end > len(d):
        return False, 'truncated', d
    if len(d) - end > 16:
        return False, 'garbage-tail', d
    return True, 'ok', d[:end]

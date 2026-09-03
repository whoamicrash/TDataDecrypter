import hashlib
import os
import re

from .constants import MIN_JPEG, PARTIAL_MIN_JPEG
from .media import (jpeg_sane, sniff_media, trim_jpeg, val_mp4,
                    val_ogg, val_tgs, val_webm, val_webp)


def make_dedupe(stats):
    seen = set()

    def write(folder, name, data, kind):
        h = hashlib.sha256(data).hexdigest()
        if h in seen:
            stats['dupes_dropped'] += 1
            return None
        seen.add(h)
        os.makedirs(folder, exist_ok=True)
        dest = os.path.join(folder, name)
        if os.path.exists(dest):
            stem, dot, ext = name.rpartition('.')
            i = 1
            while os.path.exists(dest):
                dest = os.path.join(folder, f'{stem}_{i}{dot and "." + ext}')
                i += 1
        with open(dest, 'wb') as f:
            f.write(data)
        stats[kind] = stats.get(kind, 0) + 1
        return dest

    return write


def extract_embedded(data: bytes, name: str, out_root: str, dedupe_write, stats):
    try:
        for sig in (b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'OggS',
                    b'GIF89a', b'GIF87a', b'RIFF'):
            pos = data.find(sig)
            if pos <= 0:
                continue
            ext, off = sniff_media(data[pos:pos + 64])
            if not ext or off != 0:
                continue
            payload = data[pos:]
            if ext == 'jpg':
                t = trim_jpeg(payload)
                if t and len(t) > MIN_JPEG and jpeg_sane(t):
                    return dedupe_write(os.path.join(out_root, 'photos'),
                                        f'{name}.jpg', t, 'photos_embedded')
            elif ext == 'png':
                if payload[:8] == b'\x89PNG\r\n\x1a\n' and b'IEND' in payload[-16:]:
                    return dedupe_write(os.path.join(out_root, 'photos'),
                                        f'{name}.png', payload, 'photos_embedded')
            elif ext == 'webp':
                if val_webp(payload):
                    return dedupe_write(os.path.join(out_root, 'stickers'),
                                        f'{name}.webp', payload, 'stickers_webp')
            elif ext == 'ogg':
                if val_ogg(payload):
                    return dedupe_write(os.path.join(out_root, 'voice'),
                                        f'{name}.ogg', payload, 'voice')
            elif ext == 'gif':
                return dedupe_write(os.path.join(out_root, 'files'),
                                    f'{name}.gif', payload, 'file_gif')
    except Exception:
        return None
    return None


def classify_blob(data: bytes, name: str, out_root: str, dedupe_write, stats,
                  suffix: str = ''):
    try:
        ext, off = sniff_media(data, deep=False)
        if ext is None and name.endswith('.bin'):
            ext, off = sniff_media(data, deep=True)
        if ext is None:
            stats['junk_unknown'] += 1
            return None
        payload = data[off:] if off else data
        base = re.sub(r'\.(bin|[a-z0-9]+)$', '', name) or name

        if ext in ('jpg',):
            t = trim_jpeg(payload)
            if t and len(t) > MIN_JPEG and jpeg_sane(t):
                return dedupe_write(os.path.join(out_root, 'photos'),
                                    f'{base}{suffix}.jpg', t, 'photos')
            if (payload[:3] == b'\xff\xd8\xff' and len(payload) > PARTIAL_MIN_JPEG
                    and jpeg_sane(payload)):
                return dedupe_write(os.path.join(out_root, 'photos', 'partial'),
                                    f'{base}{suffix}.jpg', payload, 'photos_partial')
            stats['broken_jpg'] += 1
            return None
        if ext == 'png':
            if payload[:8] == b'\x89PNG\r\n\x1a\n' and b'IEND' in payload[-16:]:
                return dedupe_write(os.path.join(out_root, 'photos'),
                                    f'{base}{suffix}.png', payload, 'photos')
            stats['broken_png'] += 1
            return None
        if ext == 'avif':
            return dedupe_write(os.path.join(out_root, 'photos'),
                                f'{base}{suffix}.avif', payload, 'photos')
        if ext == 'webp':
            if val_webp(payload):
                return dedupe_write(os.path.join(out_root, 'stickers'),
                                    f'{base}{suffix}.webp', payload, 'stickers_webp')
            stats['broken_webp'] += 1
            return None
        if ext == 'tgs':
            t = val_tgs(payload)
            if t:
                return dedupe_write(os.path.join(out_root, 'stickers'),
                                    f'{base}{suffix}.tgs', t, 'stickers_tgs')
            stats['broken_tgs'] += 1
            return None
        if ext == 'webm':
            if val_webm(payload):
                return dedupe_write(os.path.join(out_root, 'stickers'),
                                    f'{base}{suffix}.webm', payload, 'stickers_webm')
            stats['broken_webm'] += 1
            return None
        if ext == 'ogg':
            if val_ogg(payload):
                return dedupe_write(os.path.join(out_root, 'voice'),
                                    f'{base}{suffix}.ogg', payload, 'voice')
            stats['broken_ogg'] += 1
            return None
        if ext in ('mp4', 'mov'):
            ok, why, t = val_mp4(payload)
            if ok:
                return dedupe_write(os.path.join(out_root, 'videos'),
                                    f'{base}{suffix}.{ext}', t, 'videos')
            if why == 'no-moov' and payload[4:8] == b'ftyp' and len(payload) >= 65536:
                return dedupe_write(os.path.join(out_root, 'videos', 'partial'),
                                    f'{base}{suffix}.frag.{ext}', payload,
                                    'videos_frag')
            stats[f'mp4_{why}'] += 1
            return None
        return dedupe_write(os.path.join(out_root, 'files'),
                            f'{base}{suffix}.{ext}', payload, f'file_{ext}')
    except Exception as e:
        stats['classify_errors'] += 1
        return None

import os
import re
import struct

from .binlog import (key_kind, media_id_of, media_name, parse_binlog,
                     xxh32)
from .constants import (K_IN_SLICE, K_PART_SIZE, MAX_MERGE_BYTES,
                        MAX_SLICE_GAP, MAX_SLICES_PER_FILE, TAG_NAMES)
from .crypto import open_tdef
from .i18n import tr
from .media import sniff_media


def parse_slice_value(value: bytes):
    n = len(value)
    if n and (n % K_PART_SIZE == 0 or n == K_IN_SLICE):
        return ([(off, value[off:off + K_PART_SIZE])
                 for off in range(0, n, K_PART_SIZE)], b'', False)
    if n >= 4:
        cnt = struct.unpack('<I', value[0:4])[0]
        if 0 < cnt <= 80:
            p, parts = 4, []
            try:
                for _ in range(cnt):
                    off, size = struct.unpack('<II', value[p:p + 8])
                    p += 8
                    parts.append((off, value[p:p + size]))
                    p += size
                if p <= n:
                    return parts, value[p:], True
            except (IndexError, struct.error):
                pass
    return None, None, False


def save_blob(target: str, name: str, data: bytes, deep: bool = True) -> str:
    try:
        ext, o2 = sniff_media(data, deep=deep)
    except Exception:
        ext, o2 = None, 0
    if ext:
        dest = os.path.join(target, f'{name}.{ext}')
        payload = data[o2:] if o2 else data
    else:
        raw = os.path.join(target, 'raw')
        os.makedirs(raw, exist_ok=True)
        dest = os.path.join(raw, f'{name}.bin')
        payload = data
    with open(dest, 'wb') as f:
        f.write(payload)
    return dest


def place_to_relpath(place: bytes) -> str:
    h = ''.join(f'{b & 0x0F:X}{b >> 4:X}' for b in place)
    return h[:2] + '/' + h[2:]


def iter_place_files(root: str):
    out = []
    try:
        names = os.listdir(root)
    except OSError:
        return out
    for fn in names:
        if fn == 'binlog' or fn == 'version':
            continue
        full = os.path.join(root, fn)
        if os.path.isfile(full) and re.fullmatch(r'[0-9A-F]{14}', fn):
            out.append((fn, full))
        elif os.path.isdir(full) and re.fullmatch(r'[0-9A-F]{2}', fn):
            try:
                for f2 in os.listdir(full):
                    if re.fullmatch(r'[0-9A-F]{12}', f2):
                        out.append((fn + f2, os.path.join(full, f2)))
            except OSError:
                pass
    return out


def find_place_file(root: str, place_hex14: str):
    p = os.path.join(root, place_hex14[:2], place_hex14[2:])
    if os.path.isfile(p):
        return p
    p = os.path.join(root, place_hex14)
    if os.path.isfile(p):
        return p
    return None


def slice_runs(items):
    runs, cur, base = [], [], 0
    for it in items:
        if cur and (it[0] - cur[-1][0] > MAX_SLICE_GAP
                    or it[0] - base > MAX_SLICES_PER_FILE):
            runs.append(cur)
            cur = []
        if not cur:
            base = it[0]
        cur.append(it)
    if cur:
        runs.append(cur)
    return runs


def merge_slice_run(high, run, target, ui):
    base = run[0][0]
    base_e = run[0][2]
    by_low = {low for low, data, e in run}
    parts0, rem0, complex0 = parse_slice_value(run[0][1])
    header_case = bool(complex0 and (base + 1) not in by_low
                       and (base + 2) in by_low)
    stem = media_name(high, base, base_e[2])
    chunks = {}
    for low, data, _e in run:
        delta = low - base
        if delta > MAX_SLICES_PER_FILE:
            ui.log(tr('merge_far', name=stem,
                      off=delta * K_IN_SLICE // (1024 * 1024)), 'warn')
            continue
        parts, rem, was_complex = parse_slice_value(data)
        if low == base and header_case:
            if parts:
                for off, b in parts:
                    chunks[off] = b
            if rem:
                rparts, _, _ = parse_slice_value(rem)
                if rparts:
                    for off, b in rparts:
                        chunks[off] = b
                else:
                    chunks[0] = rem
        else:
            slice_off = ((delta - 1) * K_IN_SLICE if header_case
                         else delta * K_IN_SLICE)
            if parts:
                for off, b in parts:
                    chunks[slice_off + off] = b
            else:
                chunks[slice_off] = data
    if not chunks:
        return None
    total = max(o + len(b) for o, b in chunks.items())
    if total > MAX_MERGE_BYTES:
        ui.log(tr('merge_huge', name=stem,
                  max=MAX_MERGE_BYTES // (1024 * 1024)), 'warn')
        chunks = {o: b for o, b in chunks.items()
                  if o + len(b) <= MAX_MERGE_BYTES}
        if not chunks:
            return None
        total = max(o + len(b) for o, b in chunks.items())
    try:
        buf = bytearray(total)
    except (MemoryError, OverflowError) as e:
        ui.log(tr('merge_fail', high=f'{high:016x}', e=e), 'warn')
        return None
    filled = 0
    for off, b in chunks.items():
        buf[off:off + len(b)] = b
        filled += len(b)
    ext, _ = sniff_media(bytes(buf[:64]))
    name = stem + (f'.{ext}' if ext else '')
    with open(os.path.join(target, name), 'wb') as f:
        f.write(buf)
    entry = {'stem': stem, 'kind': key_kind(high),
             'file_id': str(media_id_of(high, base)),
             'dc': high & 0xFF,
             'tag': TAG_NAMES.get(base_e[2], base_e[2]),
             'size': total, 'stored': base_e[6], 'used': base_e[7],
             'high': f'{high:016x}', 'low': f'{base:016x}',
             'merged': True}
    return name, total, filled, entry


def process_cache_db(db_dir: str, local_key: bytes, staging_root: str, ui,
                     stats, is_media: bool, tick=None):
    saved = 0
    index_entries = []
    target = os.path.join(staging_root, 'media_cache' if is_media else 'cache')
    os.makedirs(target, exist_ok=True)
    for root, dirs, files in os.walk(db_dir):
        if tick:
            tick()
        places = {}
        if 'binlog' in files:
            try:
                content = open_tdef(os.path.join(root, 'binlog'), local_key)
                if content is not None:
                    places = parse_binlog(content)
                    ui.log(tr('binlog_ok', rel=os.path.relpath(root, db_dir),
                              n=len(places)), 'ok')
            except Exception as e:
                ui.log(tr('binlog_fail', e=e), 'warn')
        disk_places = iter_place_files(root)
        if not places and not disk_places:
            continue
        referenced = {}
        for (high, low), e in places.items():
            ppath = find_place_file(root, e[4])
            if ppath:
                referenced[ppath] = (high, low, e)
        orphan_vals = []
        for name14, full in disk_places:
            if full not in referenced:
                try:
                    content = open_tdef(full, local_key)
                except Exception:
                    content = None
                if content is not None:
                    orphan_vals.append((name14, content))
        for name14, content in orphan_vals:
            save_blob(target, name14, content, deep=not is_media)
            saved += 1
            if tick:
                tick()
        if orphan_vals:
            stats['orphan_places' + ('_media' if is_media else '')] += len(orphan_vals)
        slices_by_high = {}
        for full, (high, low, e) in referenced.items():
            try:
                val = open_tdef(full, local_key)
            except Exception:
                val = None
            if val is None:
                continue
            size = e[3] if e[3] and e[3] <= len(val) else len(val)
            data = val[:size] if size else val
            if e[5] and xxh32(data) != e[5]:
                ui.log(tr('checksum_fail', place=e[4]), 'warn')
            kind = key_kind(high)
            stem = media_name(high, low, e[2])
            index_entries.append({'stem': stem, 'kind': kind,
                                  'file_id': str(media_id_of(high, low)),
                                  'dc': (high & 0xFF) if kind in (
                                      'document', 'document_thumb', 'photo') else None,
                                  'tag': TAG_NAMES.get(e[2], e[2]),
                                  'size': len(data), 'stored': e[6], 'used': e[7],
                                  'place': e[4], 'high': f'{high:016x}', 'low': f'{low:016x}'})
            if is_media:
                slices_by_high.setdefault(high, []).append((low, data, e))
            else:
                save_blob(target, stem, data, deep=True)
                saved += 1
            if tick:
                tick()
        for high, items in slices_by_high.items():
            items.sort(key=lambda x: x[0])
            runs = slice_runs(items)
            if len(runs) > 1:
                ui.log(tr('merge_runs', high=f'{high:016x}', n=len(runs)), 'warn')
            for run in runs:
                try:
                    res = merge_slice_run(high, run, target, ui)
                except Exception as e:
                    ui.log(tr('merge_fail', high=f'{high:016x}', e=e), 'warn')
                    continue
                if res is None:
                    continue
                name, total, filled, entry = res
                saved += 1
                index_entries.append(entry)
                if tick:
                    tick()
                if filled < total:
                    ui.log(tr('merged_holes', name=name, filled=filled,
                              total=total), 'warn')
    return saved, index_entries

import os
import re
import struct

from .constants import (GOOD_BOXES, K_IN_SLICE, K_PART_SIZE,
                        MAX_MERGE_BYTES)
from .exceptions import CancelledError
from .i18n import tr
from .media import mp4_walk, sniff_media


def parse_slice_map(value: bytes, max_size: int):
    n = len(value)
    if n and (n % K_PART_SIZE == 0 or n == max_size):
        return {o: value[o:o + K_PART_SIZE] for o in range(0, n, K_PART_SIZE)}, b''
    if n < 4:
        return None, None
    cnt = struct.unpack('<I', value[0:4])[0]
    if cnt == 0 or cnt > 80:
        return None, None
    p, parts = 4, {}
    for _ in range(cnt):
        if p + 8 > n:
            return None, None
        off, size = struct.unpack('<II', value[p:p + 8])
        p += 8
        if size == 0 or p + size > n:
            return None, None
        if off >= max_size or size > max_size or off + size > max_size:
            return None, None
        parts[off] = value[p:p + size]
        p += size
    return parts, value[p:]


def try_slice_parse(data: bytes, max_size: int = K_IN_SLICE):
    m, rem = parse_slice_map(data, max_size)
    if m is not None:
        return m, rem
    n = len(data)
    trimmed = n - (n % K_PART_SIZE) if n % K_PART_SIZE else n
    for cand in (trimmed, min(n, max_size)):
        if 0 < cand < n:
            m, rem = parse_slice_map(data[:cand], max_size)
            if m is not None:
                return m, rem
    return None, None


def is_slice_parts(parts):
    if not parts:
        return False
    for off, b in parts.items():
        if off % K_PART_SIZE != 0:
            return False
        if len(b) != K_PART_SIZE and len(b) % K_PART_SIZE != 0:
            return False
    return max(o + len(b) for o, b in parts.items()) <= K_IN_SLICE


class ChunkStore:

    def __init__(self):
        self.chunks = {}

    def add(self, off, b):
        if b:
            self.chunks[off] = b

    def get(self, off, n):
        for o, b in self.chunks.items():
            if o <= off < o + len(b):
                take = b[off - o: off - o + n]
                return take if len(take) == n else None
        return None

    def known_bytes(self):
        return sum(len(b) for b in self.chunks.values())

    def span(self):
        return max((o + len(b) for o, b in self.chunks.items()), default=0)

    def to_buffer(self, total):
        buf = bytearray(total)
        filled = 0
        for o, b in self.chunks.items():
            if o < total:
                end = min(o + len(b), total)
                buf[o:end] = b[:end - o]
                filled += end - o
        return buf, filled

    def verify(self, abs_off, data):
        for o, b in self.chunks.items():
            if o <= abs_off < o + len(b):
                take = b[abs_off - o: abs_off - o + len(data)]
                if len(take) != len(data):
                    if not take:
                        return None
                    return take == data[:len(take)]
                return take == data
        return None

    def overlap_volume(self, abs_off, n):
        for o, b in self.chunks.items():
            if o <= abs_off < o + len(b):
                return min(o + len(b), abs_off + n) - abs_off
        return 0


def walk_boxes_store(store: ChunkStore, cap: int):
    boxes = []
    pos = 0
    while pos + 8 <= cap:
        hdr = store.get(pos, 8)
        if hdr is None:
            return None, boxes
        size = struct.unpack('>I', hdr[:4])[0]
        typ = hdr[4:8]
        if size == 1:
            ext = store.get(pos + 8, 8)
            if ext is None:
                return None, boxes
            size = struct.unpack('>Q', ext)[0]
            if size < 16:
                return pos, boxes
        elif size < 8:
            return pos, boxes
        if typ not in GOOD_BOXES:
            return pos, boxes
        boxes.append((pos, size, typ))
        if pos + size > cap:
            return pos + size, boxes
        pos += size
    return pos, boxes


def rebuild_videos(mc_staging: str, videos_dir: str, partial_dir: str, ui,
                   stats, dedupe_write, cancel_check=None):
    used_files = set()
    pool = []
    for root, dirs, files in os.walk(mc_staging):
        is_raw = os.path.basename(root) == 'raw'
        for f in files:
            path = os.path.join(root, f)
            stem = f.rsplit('.', 1)[0] if '.' in f else f
            if is_raw:
                pool.append(path)
            elif re.fullmatch(r'[0-9A-F]{14}', stem):
                pool.append(path)
    if not pool:
        return used_files

    headers, candidates = [], []
    for path in pool:
        if cancel_check and cancel_check():
            raise CancelledError()
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
        except OSError:
            continue
        try:
            m1, rem1 = parse_slice_map(data, 512 * 1024 * 1024)
            if m1 is not None and 0 in m1 and m1[0][4:8] == b'ftyp':
                store = ChunkStore()
                for off, b in m1.items():
                    store.add(off, b)
                if rem1:
                    m2, _ = try_slice_parse(rem1, K_IN_SLICE)
                    if m2:
                        for off, b in m2.items():
                            store.add(off, b)
                    elif len(rem1) >= K_PART_SIZE:
                        store.add(0, rem1)
                headers.append(dict(path=path, name=os.path.basename(path),
                                    store=store))
                continue
            m, rem = try_slice_parse(data, K_IN_SLICE)
            sniffed, _ = sniff_media(data[:64])
            if (m is not None and not rem and is_slice_parts(m)
                    and sniffed is None):
                candidates.append((path, m))
                continue
        except Exception as e:
            ui.log(tr('parse_skip', name=os.path.basename(path), e=e), 'warn')

    if not headers:
        ui.log(tr('no_headers'))
        return used_files

    videos = []
    for h in headers:
        probe_off = 0
        probe = h['store'].get(0, 4096)
        target = None
        if probe:
            for v in videos:
                if v['store'].verify(0, probe) is True:
                    target = v
                    break
        if target is not None:
            for off, b in h['store'].chunks.items():
                target['store'].add(off, b)
            target['names'].append(h['name'])
            used_files.add(h['path'])
        else:
            h['names'] = [h['name']]
            videos.append(h)
            used_files.add(h['path'])
    if len(videos) < len(headers):
        ui.log(tr('headers_merged', n=len(headers) - len(videos)))

    for v in videos:
        span = v['store'].span()
        end_by_boxes, boxes = walk_boxes_store(v['store'], span)
        v['T'] = min(max(end_by_boxes or 0, span), MAX_MERGE_BYTES)
        v['boxes'] = [t.decode('latin1') for _, _, t in boxes]
        v['known'] = v['store'].known_bytes()

    ui.log(tr('recon_stats', n=len(videos), m=len(candidates)), 'ok')

    assigns = []
    used_c = set()

    def slot_taken(v, k):
        return any(a[0] is v and a[1] == k for a in assigns)

    for v in videos:
        T = v['T']
        if T <= K_IN_SLICE:
            continue
        n_slices = (T + K_IN_SLICE - 1) // K_IN_SLICE
        for k in range(1, n_slices + 1):
            if slot_taken(v, k):
                continue
            slot_start = (k - 1) * K_IN_SLICE
            slot_max = min(K_IN_SLICE, T - slot_start)
            for ci, (cpath, cm) in enumerate(candidates):
                if ci in used_c:
                    continue
                cspan = max(o + len(b) for o, b in cm.items())
                if cspan > slot_max:
                    continue
                ok = None
                vol = 0
                for rel_off, b in cm.items():
                    res = v['store'].verify(slot_start + rel_off, b)
                    if res is not None:
                        vol += v['store'].overlap_volume(slot_start + rel_off, len(b))
                        if ok is None:
                            ok = res
                        elif not res:
                            ok = False
                if ok is True and vol >= 4096:
                    assigns.append((v, k, (cpath, cm),
                                    tr('mode_verified', kb=vol // 1024)))
                    used_c.add(ci)
                    break

    verified_vids = {id(a[0]) for a in assigns if 'VERIFIED' in a[3]}
    for v in videos:
        if id(v) not in verified_vids:
            continue
        T = v['T']
        n_slices = (T + K_IN_SLICE - 1) // K_IN_SLICE
        for k in range(2, n_slices + 1):
            if slot_taken(v, k):
                continue
            slot_start = (k - 1) * K_IN_SLICE
            if v['store'].overlap_volume(slot_start, K_IN_SLICE) > 0:
                continue
            for ci, (cpath, cm) in enumerate(candidates):
                if ci in used_c:
                    continue
                cspan = max(o + len(b) for o, b in cm.items())
                if cspan == K_IN_SLICE:
                    assigns.append((v, k, (cpath, cm), tr('mode_assumed')))
                    used_c.add(ci)
                    break

    for ci, (cpath, cm) in enumerate(candidates):
        if ci in used_c:
            continue
        cspan = max(o + len(b) for o, b in cm.items())
        best = None
        for v in videos:
            T = v['T']
            if T <= K_IN_SLICE:
                continue
            n_slices = (T + K_IN_SLICE - 1) // K_IN_SLICE
            k = n_slices
            if slot_taken(v, k):
                continue
            slot_start = (k - 1) * K_IN_SLICE
            slot_max = T - slot_start
            if cspan > slot_max:
                continue
            if v['store'].overlap_volume(slot_start, slot_max) > 0:
                continue
            outcome = (v['store'].known_bytes() + cspan) / T
            if best is None or outcome > best[0]:
                best = (outcome, v, k)
        if best:
            _, v, k = best
            assigns.append((v, k, (cpath, cm),
                            tr('mode_assumed_tail',
                               pct=f'{best[0] * 100:.0f}')))
            used_c.add(ci)

    for v, k, (cpath, cm), mode in assigns:
        used_files.add(cpath)
        ui.log(tr('slice_assign', name=v['names'][0], k=k,
                  file=os.path.basename(cpath), mode=mode))

    for v in videos:
        if cancel_check and cancel_check():
            raise CancelledError()
        try:
            for a in assigns:
                if a[0] is v:
                    slot_start = (a[1] - 1) * K_IN_SLICE
                    for rel_off, b in a[2][1].items():
                        v['store'].add(slot_start + rel_off, b)
            T = v['T']
            buf, filled = v['store'].to_buffer(T)
            holes = T - filled
            base = re.sub(r'\.(bin|mp4|mov|webm)$', '', v['names'][0])
            fin_boxes, _, _ = mp4_walk(bytes(buf))
            has_moov = any(t == b'moov' for _, _, t in fin_boxes)
            if holes <= 0:
                out_name = f'{base}.mp4'
                folder = videos_dir
                status = 'COMPLETE'
            elif has_moov:
                out_name = f'{base}.partial.mp4'
                folder = partial_dir
                status = tr('status_partial', f=f'{filled / 1048576:.1f}',
                            t=f'{T / 1048576:.1f}', p=f'{filled / T * 100:.0f}')
            else:
                out_name = f'{base}.frag.mp4'
                folder = partial_dir
                status = tr('status_fragment', f=f'{filled / 1048576:.1f}',
                            t=f'{T / 1048576:.1f}', p=f'{filled / T * 100:.0f}')
            dedupe_write(folder, out_name, bytes(buf), 'videos')
            ui.log(f"  [+] {out_name}: {status} [{', '.join(v['boxes'] or ['?'])}]",
                   'ok')
        except Exception as e:
            ui.log(tr('assembly_fail', name=v['names'][0], e=e), 'warn')

    leftover = len(candidates) - len(used_c)
    if leftover:
        ui.log(tr('unassigned', n=leftover), 'warn')
    stats['recon_headers'] = len(videos)
    stats['recon_slices_used'] = len(used_c)
    return used_files

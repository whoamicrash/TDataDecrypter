import struct

from .constants import KEY_KINDS, M32, TAG_PREFIX


def _rotl(v, r):
    return ((v << r) | (v >> (32 - r))) & M32


def xxh32(data: bytes, seed: int = 0) -> int:
    P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    n, i = len(data), 0
    if n >= 16:
        v1 = (seed + P1 + P2) & M32
        v2 = (seed + P2) & M32
        v3 = seed & M32
        v4 = (seed - P1) & M32
        while i + 16 <= n:
            for idx, acc in ((0, v1), (1, v2), (2, v3), (3, v4)):
                k = int.from_bytes(data[i + idx * 4:i + idx * 4 + 4], 'little')
                acc = (acc + k * P2) & M32
                acc = _rotl(acc, 13)
                acc = (acc * P1) & M32
                if idx == 0: v1 = acc
                elif idx == 1: v2 = acc
                elif idx == 2: v3 = acc
                else: v4 = acc
            i += 16
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & M32
    else:
        h = (seed + P5) & M32
    h = (h + n) & M32
    while i + 4 <= n:
        h = (h + int.from_bytes(data[i:i + 4], 'little') * P3) & M32
        h = (_rotl(h, 17) * P4) & M32
        i += 4
    while i < n:
        h = (h + data[i] * P5) & M32
        h = (_rotl(h, 11) * P1) & M32
        i += 1
    h ^= h >> 15
    h = (h * P2) & M32
    h ^= h >> 13
    h = (h * P3) & M32
    h ^= h >> 16
    return h


def parse_binlog(content: bytes):
    entries = {}
    if len(content) < 16:
        return entries
    flags = struct.unpack('<I', content[0:4])[0] >> 8
    track_time = bool(flags & 0x01)
    part_size = 48 if track_time else 32
    n, p = len(content), 16

    def read_store(rec):
        e = [struct.unpack('<Q', rec[16:24])[0],
             struct.unpack('<Q', rec[24:32])[0],
             rec[1],
             int.from_bytes(rec[2:5], 'little'),
             ''.join(f'{b & 0x0F:X}{b >> 4:X}' for b in rec[5:12]),
             struct.unpack('<I', rec[12:16])[0]]
        if track_time:
            e.append(struct.unpack('<I', rec[40:44])[0])
            e.append(struct.unpack('<I', rec[32:36])[0]
                     | (struct.unpack('<I', rec[36:40])[0] << 32))
        else:
            e.extend([0, 0])
        return tuple(e)

    while p < n:
        t = content[p]
        try:
            if t == 0x01:
                rec = content[p:p + part_size]
                p += part_size
                e = read_store(rec)
                entries[e[0], e[1]] = e
            elif t == 0x02:
                count = int.from_bytes(content[p + 1:p + 4], 'little')
                p += 16
                for _ in range(count):
                    rec = content[p:p + part_size]
                    p += part_size
                    e = read_store(rec)
                    entries[e[0], e[1]] = e
            elif t == 0x03:
                count = int.from_bytes(content[p + 1:p + 4], 'little')
                p += 16 + 16 * count
            elif t == 0x04:
                count = int.from_bytes(content[p + 1:p + 4], 'little')
                rel1 = struct.unpack('<I', content[p + 4:p + 8])[0]
                rel2 = struct.unpack('<I', content[p + 8:p + 12])[0]
                use = rel1 | (rel2 << 32)
                q = p + 16
                for _ in range(count):
                    k = struct.unpack('<QQ', content[q:q + 16])
                    if k in entries:
                        old = entries[k]
                        entries[k] = old[:7] + (use,)
                    q += 16
                p = q
            else:
                break
        except (IndexError, struct.error):
            break
    return entries


def key_kind(high: int) -> str:
    for mask, val, name in KEY_KINDS:
        if (high & mask) == val:
            return name
    return 'photo'


def media_id_of(high: int, low: int):
    kind = key_kind(high)
    if kind in ('document', 'document_thumb', 'album_thumb'):
        return low
    if kind in ('document_chunk', 'photo_chunk'):
        return (low >> 32) & 0xFFFFFFFF
    return low


def media_name(high: int, low: int, tag: int) -> str:
    kind = key_kind(high)
    if kind in ('document', 'document_thumb', 'album_thumb'):
        return f'{TAG_PREFIX.get(tag, "doc")}_{low}'
    if kind in ('document_chunk', 'photo_chunk'):
        return f"{'video' if kind == 'document_chunk' else 'photo'}_{(low >> 32) & 0xFFFFFFFF}"
    sl = chr((high >> 16) & 0xFF)
    sfx = f'_{sl}' if (sl.isascii() and sl.isalpha()) else ''
    return f'photo_{low}{sfx}'

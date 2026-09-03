import hashlib
import os
import struct

from .constants import LSK_SUBFILES
from .crypto import decrypt_local
from .i18n import tr


class QStream:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def _take(self, n):
        if self.p + n > len(self.d):
            raise EOFError
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def u32(self):
        return struct.unpack('>I', self._take(4))[0]

    def i32(self):
        return struct.unpack('>i', self._take(4))[0]

    def u64(self):
        return struct.unpack('>Q', self._take(8))[0]

    def i64(self):
        return struct.unpack('>q', self._take(8))[0]

    def u16(self):
        return struct.unpack('>H', self._take(2))[0]

    def qba(self) -> bytes:
        n = self.u32()
        if n == 0xFFFFFFFF:
            return b''
        return self._take(n)

    def qstr(self) -> str:
        n = self.u32()
        if n == 0xFFFFFFFF:
            return ''
        return self._take(n).decode('utf-16-be', errors='ignore')

    def raw(self, n):
        return self._take(n)

    def at_end(self):
        return self.p >= len(self.d)


def to_file_part(val: int) -> str:
    return f'{val:016X}'[::-1]


def read_tdf(path: str):
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    if len(raw) < 24 or raw[:4] != b'TDF$':
        return None
    version = struct.unpack('<i', raw[4:8])[0]
    data, sig = raw[8:-16], raw[-16:]
    good = hashlib.md5(data + struct.pack('<i', len(data))
                       + struct.pack('<i', version) + b'TDF$').digest() == sig
    return version, data, good


def find_key_file(tdata: str):
    names = ['key_datass', 'key_datas0', 'key_datas1', 'key_datas',
             'key_data0', 'key_data1']
    for n in names:
        p = os.path.join(tdata, n)
        if os.path.isfile(p):
            return p
    return None


def parse_map(path: str, local_key: bytes):
    drafts, self_data, subkeys, errors = [], None, {}, []
    tdf = read_tdf(path)
    if not tdf:
        return drafts, self_data, subkeys, [tr('map_not_tdf',
                                               name=os.path.basename(path))]
    _, data, _ = tdf
    st = QStream(data)
    try:
        st.qba()
        st.qba()
        enc = st.qba()
    except EOFError:
        return drafts, self_data, subkeys, [tr('map_bad_struct',
                                               name=os.path.basename(path))]
    payload = decrypt_local(local_key, enc)
    if payload is None:
        return drafts, self_data, subkeys, [tr('map_not_decrypted',
                                               name=os.path.basename(path))]
    m = QStream(payload)
    while not m.at_end():
        try:
            kt = m.u32()
            if kt in (0x01, 0x02, 0x1d):
                cnt = m.u32()
                for _ in range(cnt):
                    fk, pid = m.u64(), m.u64()
                    if kt == 0x01:
                        drafts.append((pid, fk))
            elif kt in (0x03, 0x05, 0x06):
                cnt = m.u32()
                for _ in range(cnt):
                    m.u64(); m.u64(); m.u64(); m.i32()
            elif kt == 0x15:
                self_data = m.qba()
            elif kt == 0x19:
                m.qba(); m.qba()
            elif kt == 0x14:
                m.u64(); m.u64()
            elif kt == 0x10:
                ks = [m.u64() for _ in range(4)]
                subkeys['stickers'] = ks[0]
            elif kt in (0x16, 0x17):
                ks = [m.u64() for _ in range(3)]
                subkeys['masks' if kt == 0x16 else 'emoji'] = ks[0]
            elif kt in LSK_SUBFILES:
                fk = m.u64()
                if fk:
                    subkeys[LSK_SUBFILES[kt]] = fk
            else:
                m.u64()
        except (EOFError, struct.error):
            errors.append(tr('map_truncated', name=os.path.basename(path)))
            break
    return drafts, self_data, subkeys, errors

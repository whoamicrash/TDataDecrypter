import os
import re
import shutil
import subprocess
import sys

from .crypto import create_local_key, create_legacy_local_key, decrypt_local
from .i18n import tr
from .tdf import QStream, find_key_file, read_tdf


def john_hash(tdata: str):
    path = find_key_file(tdata)
    if not path:
        return None
    tdf = read_tdf(path)
    if not tdf:
        return None
    _, data, _ = tdf
    st = QStream(data)
    try:
        salt, key_enc = st.qba(), st.qba()
    except EOFError:
        return None
    if len(salt) != 32 or not key_enc:
        return None
    return f'$telegram$2*100000*{salt.hex()}*{key_enc.hex()}'


def find_john():
    """Найти исполняемый файл John the Ripper (PATH + типичные места)."""
    p = shutil.which('john')
    if p:
        return p
    exe = 'john.exe' if sys.platform.startswith('win') else 'john'
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    home = os.path.expanduser('~')
    cands = [
        os.path.join(base, 'john', 'run', exe),
        os.path.join(base, 'run', exe),
        os.path.join(base, exe),
        os.path.join(home, 'john', 'run', exe),
    ]
    if sys.platform.startswith('win'):
        cands.append(r'C:\john\run\john.exe')
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def no_window():
    kw = {}
    if sys.platform.startswith('win'):
        kw['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
    return kw


def john_cmd(john, pot, session, hashfile, wordlist='', mask='', rules=False):
    """Командная строка запуска JtR для формата telegram."""
    cmd = [john, '--format=telegram', '--pot=' + pot, '--session=' + session]
    if mask:
        cmd.append('--mask=' + mask)
    elif wordlist:
        cmd.append('--wordlist=' + wordlist)
        if rules:
            cmd.append('--rules')
    cmd.append(hashfile)
    return cmd


def john_show(john, pot, hashfile):
    """Взят ли уже пароль: разбор вывода `john --show`."""
    try:
        r = subprocess.run([john, '--pot=' + pot, '--show',
                            '--format=telegram', hashfile],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace',
                           timeout=60, **no_window())
    except Exception:
        return None
    for line in ((r.stdout or '') + '\n' + (r.stderr or '')).splitlines():
        m = re.match(r'^\$telegram\$2\*[^:]+:(.+)$', line.strip())
        if m:
            return m.group(1)
    return None


def john_supports_telegram(john):
    """Умеет ли сборка JtR формат telegram (только jumbo)."""
    try:
        r = subprocess.run([john, '--list=formats'], capture_output=True,
                           text=True, encoding='utf-8', errors='replace',
                           timeout=60, **no_window())
    except Exception:
        return False
    fmts = re.split(r'[,\s]+', ((r.stdout or '') + ' ' + (r.stderr or '')))
    return 'telegram' in fmts


def extract_local_key(tdata: str, passcode: bytes = b''):
    path = find_key_file(tdata)
    if not path:
        return None, tr('key_missing')
    tdf = read_tdf(path)
    if not tdf:
        return None, tr('key_not_tdf', name=os.path.basename(path))
    version, data, _ = tdf
    st = QStream(data)
    try:
        salt, key_enc, info_enc = st.qba(), st.qba(), st.qba()
    except EOFError:
        return None, tr('key_parse_fail', name=os.path.basename(path))
    if len(salt) != 32:
        return None, tr('key_bad_salt', n=len(salt))

    attempts = [('modern', create_local_key(passcode, salt))]
    if not passcode:
        attempts.append(('legacy', create_legacy_local_key(passcode, salt)))

    for kind, pkey in attempts:
        payload = decrypt_local(pkey, key_enc)
        if not payload or len(payload) != 256:
            continue
        info = decrypt_local(payload, info_enc)
        note = ''
        if info:
            ist = QStream(info)
            try:
                count = ist.i32()
                if 1 <= count <= 20:
                    note = tr('key_info_ok', n=count)
            except (EOFError, struct.error):
                pass
        return payload, tr('key_ok', name=os.path.basename(path),
                           kind=kind, version=version, note=note)
    if passcode:
        return None, tr('key_wrong_pass')
    jh = john_hash(tdata)
    hint = tr('key_john_hint') if jh else ''
    return None, tr('key_no_decrypt', hint=hint)

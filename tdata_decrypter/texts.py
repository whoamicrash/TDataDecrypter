import re
import struct
from collections import defaultdict

from .i18n import tr

_RE_UTF16BE = re.compile(rb'(?:\x00[\x20-\x7E]|\x00[\x0A\x0D]|\x04[\x00-\xFF]){6,}')

_RE_UTF16LE = re.compile(rb'(?:[\x20-\x7E]\x00|[\x0A\x0D]\x00|[\x00-\xFF]\x04){6,}')

_RE_UTF8 = re.compile(rb'(?:[\x20-\x7E]|\xD0[\x80-\xBF]|\xD1[\x80-\x9F]){8,}')


def _is_suspect(ch):
    cp = ord(ch)
    if cp < 0x20:
        return cp not in (0x09, 0x0A, 0x0D)
    if 0x3400 <= cp <= 0x9FFF:
        return True
    if 0xAC00 <= cp <= 0xD7AF or 0x1100 <= cp <= 0x11FF:
        return True
    if 0x3040 <= cp <= 0x30FF or 0xFF66 <= cp <= 0xFF9D:
        return True
    if 0xE000 <= cp <= 0xF8FF or 0xF900 <= cp <= 0xFAFF:
        return True
    if 0x10000 <= cp < 0x1F300:
        return True
    return False


_VOWELS = set('aeiouyAEIOUYаоиеэюяуАОИЕЭЮЯУёЁ')

_EN_BIG = set('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha '
              'as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta '
              'la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie '
              'ma sm em'.split())


_RU_BIG = set('ст но ен то на ни ра по ко ми ва пр ас ро го де та са ал ер об че ак ло ин ес ли '
              'во од ен ов от ре ме си гр зн вы йт ел да не за мо аа ба ел ам ог со оо об ще ие ки '
              'ла ые ую уч ши ок ор ем аз тр ва ич го ет ой ри ым ус ум им ит ил ив ее еш лу ня '
              'ты се ру ль дь ть бе ге ше це йк йи хе ша щу ща'.split())


def _word_like_score(s: str) -> float:
    t = ''.join(ch for ch in s.lower() if ch.isalpha())
    if len(t) < 4:
        return 1.0
    bigrams = [t[i:i + 2] for i in range(len(t) - 1)]
    hits = sum(1 for b in bigrams if b in _EN_BIG or b in _RU_BIG)
    return hits / len(bigrams)


def _text_ok(s: str) -> bool:
    s = s.strip()
    if not s or len(s) < 4:
        return False
    suspect = sum(1 for ch in s if _is_suspect(ch))
    if suspect:
        return False
    letters = sum(ch.isalpha() for ch in s)
    if letters >= 3 and letters >= 0.3 * len(s):
        latin = [ch for ch in s if ch.isascii() and ch.isalpha()]
        if latin and len(latin) >= 4:
            vows = sum(1 for ch in latin if ch in _VOWELS)
            if vows / len(latin) < 0.15 and not any(c in s for c in './:@#'):
                return False
        if (not any(c in s for c in ' ./:@#-') and len(s) >= 7
                and _word_like_score(s) < 0.25):
            return False
        return True
    digits = sum(ch.isdigit() for ch in s)
    if len(s) >= 7 and digits >= 7:
        return True
    return False


def extract_qstrings(data: bytes):
    out, i, n = [], 0, len(data)
    while i + 4 <= n:
        ln = struct.unpack('>I', data[i:i + 4])[0]
        if 4 <= ln <= 8192 and ln % 2 == 0 and i + 4 + ln <= n:
            try:
                s = data[i + 4:i + 4 + ln].decode('utf-16-be')
                if _text_ok(s):
                    out.append(s)
                    i += 4 + ln
                    continue
            except UnicodeDecodeError:
                pass
        i += 1
    return out


def _regex_texts(data: bytes, use_le: bool = True):
    found = []
    for m in _RE_UTF16BE.finditer(data):
        try:
            s = m.group().decode('utf-16-be')
        except UnicodeDecodeError:
            continue
        if _text_ok(s):
            found.append(s)
    for m in _RE_UTF8.finditer(data):
        try:
            s = m.group().decode('utf-8')
        except UnicodeDecodeError:
            continue
        if _text_ok(s):
            found.append(s)
    if use_le and not found:
        for m in _RE_UTF16LE.finditer(data):
            try:
                s = m.group().decode('utf-16-le')
            except UnicodeDecodeError:
                continue
            if _text_ok(s):
                found.append(s)
    return found


def extract_texts(data: bytes):
    qstr_list = extract_qstrings(data)
    found = list(qstr_list)
    found += _regex_texts(data, use_le=not found)
    seen, uniq = set(), []
    for s in found:
        s = ' '.join(s.split())
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    cleaned = []
    for s in uniq:
        junky = False
        for o in uniq:
            if o != s and len(o) < len(s) and o in s and len(o) >= 0.6 * len(s):
                junky = True
                break
        if not junky:
            cleaned.append(s)
    out = []
    for s in cleaned:
        if not any(t != s and s in t for t in cleaned):
            out.append(s)
    return out


def parse_self_user_id(data: bytes):
    if not data or len(data) < 12:
        return None
    v32 = struct.unpack('<I', data[8:12])[0]
    v64 = struct.unpack('<Q', data[8:16])[0] if len(data) >= 16 else 0
    if (v64 >> 32) == 0:
        uid = v32
    elif v64 < (1 << 33):
        uid = v64
    else:
        uid = v32
    return uid if 0 < uid < (1 << 40) else None


_CLEAN_BIGRAMS = set('''th he an in er re on at en nd ti es or te of ed is it al ar st to nt ng
se as ot le ou ve co de ro io li el ma ca me hi ne ra ce ri om ur be ch ll si
yo or ut us am et mo'''.split())

_JUNK_CHARS = set('^`|~\\{}[]<>#$%&*+=_')

_VOWELS2 = set('aeiouyAEIOUYаеёиоуыэюяАЕЁИОУЫЭЮЯ')


def _bigram_score(s):
    b = [s[i:i + 2].lower() for i in range(len(s) - 1)]
    if not b:
        return 0.0
    good = sum(1 for x in b if x.isalpha() and x in _CLEAN_BIGRAMS)
    return good / len(b)


def hump_check(t):
    humps = re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z][a-z]*|[a-z]+", t)
    if not humps:
        return False
    if t.islower():
        return len(t) >= 6 and sum(1 for c in t if c in _VOWELS2) / len(t) >= 0.25
    WHITELIST_2 = ('mr', 'mrs', 'st', 'dr', 'tv', 'hd', 'xd', 'ok', 'go', 'do')
    for h in humps:
        if len(h) < 2:
            return False
        if h.isupper() and len(h) > 4:
            return False
        if not h[0].isupper():
            return False
        if len(h) == 2 and h.lower() not in WHITELIST_2 and not any(c in _VOWELS2 for c in h):
            return False
    return len(t) >= 3


def is_keep(text):
    t = text.strip()
    if not t:
        return False
    if re.search(r'[а-яёА-ЯЁ]{3,}', t):
        return True
    if re.search(r'@[A-Za-z0-9_]{3,}', t):
        return True
    if re.fullmatch(r'/[A-Za-z0-9_]{3,}', t):
        return True
    if re.search(r'(https?://|t\.me|\.com|\.org|\.ru\b|\.net|C:/|[A-Za-z]:\\\\'
                 r'|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                 r'|[0-9a-f]{1,4}(:[0-9a-f]{1,4}){3,}'
                 r'|\{[0-9a-f-]{8,}\}'
                 r'|\b\w+\.(webm|mp4|mov|jpg|jpeg|png|gif|pdf|zip|mp3|ogg|tgs|webp|docx?)\b)', t):
        return True
    if re.search(r'_by_|by[A-Z][a-z]|Bot\b', t):
        return True
    if re.search(r'\b\d+[КМГкмг][Ббб]?\b|\b\d{1,2}:\d{2}\b|\+\d{7,}', t):
        return True
    if '_' in t and re.fullmatch(r'[A-Za-z0-9_]{3,}', t):
        parts = [p for p in t.split('_') if p]

        def _part_ok(p):
            return p.isdigit() or (len(p) >= 3
                                   and sum(c in _VOWELS2 for c in p) / len(p) >= 0.25)

        if parts and all(_part_ok(p) for p in parts):
            return True
    letters = [c for c in t if c.isalpha()]
    if not letters:
        return bool(re.fullmatch(r'[\w\s.,:+/-]{2,}', t))
    if any(c in _JUNK_CHARS for c in t):
        return False
    alpha_part = re.sub(r'[^A-Za-z]', '', t)
    if alpha_part and len(alpha_part) / max(len(t), 1) > 0.7:
        return hump_check(alpha_part)
    words = t.split()
    if len(words) >= 2 and all(len(w) >= 2 for w in words):
        return True
    return False


_SRC_NAME_MAP = {'self': 'src_self', 'settingss': 'src_settings',
                 'usertag': 'src_usertag'}


def source_title(tag: str) -> str:
    base = tag.split('#')[0]
    if base.startswith('self@'):
        return tr('src_self_id', id=base[5:])
    if base in _SRC_NAME_MAP:
        return tr(_SRC_NAME_MAP[base])
    if re.fullmatch(r'[0-9A-F]{16}', base):
        return tr('src_account', base=base)
    return tr('src_other', tag=tag)


def clean_dump(dump_path: str, out_path: str, ui):
    groups = defaultdict(list)
    kept = dropped = 0
    try:
        with open(dump_path, encoding='utf-8') as f:
            lines = f.read().splitlines()
    except OSError:
        return 0, 0
    for line in lines:
        m = re.match(r'\[([^\]]+)\]\s?(.*)', line)
        if not m:
            continue
        tag, text = m.group(1), m.group(2)
        try:
            ok = is_keep(text)
        except Exception:
            ok = False
        if ok:
            groups[tag].append(text)
            kept += 1
        else:
            dropped += 1
    out = [tr('texts_title')] + tr('texts_note').split('\n') + ['=' * 64, '']
    def _gkey(t):
        if t.startswith('self@'):
            rest = t[5:]
            if rest.isdigit():
                return (0, int(rest), '')
            return (0, 1 << 62, rest)
        return (1, -len(groups[t]), t)

    for tag in sorted(groups, key=_gkey):
        out.append(tr('texts_group', title=source_title(tag), n=len(groups[tag])))
        for text in groups[tag]:
            out.append(text)
        out.append('')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))
    return kept, dropped

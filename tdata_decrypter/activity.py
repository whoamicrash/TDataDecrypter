import json
import os
import struct

from .constants import MODERN_IMAGE_TAG, PEER_VERSION_TAG
from .crypto import decrypt_local
from .i18n import tr
from .tdf import QStream, read_tdf, to_file_part


def decode_peer_id(v: int):
    if v & 0x0080000000000000:
        stripped = v & ~0x0080000000000000
        shift = (stripped >> 48) & 0xFF
        bare = stripped & ((1 << 48) - 1)
    else:
        nib = (v >> 32) & 0xF
        bare = v & 0xFFFFFFFF
        shift = {0: 0, 1: 1, 2: 2, 0xF: 0x7F}.get(nib, nib)
    kind = {0: 'user', 1: 'chat', 2: 'channel', 0x7F: 'fake'}.get(shift, 'peer')
    return kind, bare


def _skip_image_location(st: QStream, appver: int):
    tag = st.i32()
    if tag == MODERN_IMAGE_TAG:
        st.qba()
    else:
        st.i32(); st.i32(); st.u64(); st.i32(); st.u64()
        if appver >= 1003013:
            st.qba()


def read_peer(st: QStream, appver: int):
    pid = st.u64()
    vtag = st.u64()
    kind, bare = decode_peer_id(pid)
    ver = 0
    if vtag == PEER_VERSION_TAG:
        ver = st.i32()
        st.u64()
    _skip_image_location(st, appver)
    if ver > 0:
        st.i32()
    out = {'type': kind, 'id': bare}
    if kind == 'user':
        first, last = st.qstr(), st.qstr()
        out['name'] = (first + ' ' + last).strip()
        out['phone'] = st.qstr()
        out['username'] = st.qstr()
        st.u64()
        if appver >= 9012:
            st.i32()
        if appver >= 9016:
            st.qstr()
        st.u32(); st.i32(); st.i32()
    elif kind == 'chat':
        out['name'] = st.qstr()
        st.i32(); st.i32(); st.i32(); st.i32(); st.i32(); st.u32()
        st.qstr()
    elif kind == 'channel':
        out['name'] = st.qstr()
        st.u64(); st.i32(); st.i32(); st.i32(); st.u32()
        st.qstr()
    else:
        raise EOFError('unknown peer type')
    return out


def parse_playback(data: bytes):
    st, out = QStream(data), []
    try:
        for _ in range(st.u32()):
            out.append({'document_id': st.u64(), 'position_ms': st.i64()})
    except (EOFError, struct.error):
        pass
    return out


def parse_search_suggestions(data: bytes):
    st = QStream(data)
    out = {'top_peers': [], 'recent_peers': []}
    try:
        top_ba, rec_ba = st.qba(), st.qba()
    except (EOFError, struct.error):
        return out
    try:
        t = QStream(top_ba)
        appver, disabled, cnt = t.u32(), t.u32(), t.u32()
        if 0 < cnt <= 10000:
            for _ in range(cnt):
                p = read_peer(t, appver)
                p['rating'] = t.u64()
                out['top_peers'].append(p)
    except (EOFError, struct.error):
        pass
    try:
        r = QStream(rec_ba)
        appver, cnt = r.u32(), r.u32()
        if 0 < cnt <= 10000:
            for _ in range(cnt):
                out['recent_peers'].append(read_peer(r, appver))
    except (EOFError, struct.error):
        pass
    return out


def parse_hashtags_bots(data: bytes):
    st = QStream(data)
    out = {'sent_hashtags': [], 'search_hashtags': [], 'bots': []}
    try:
        wcnt, scnt = st.u32(), st.u32()
        for _ in range(wcnt):
            tag = st.qstr()
            score = st.u16()
            if tag:
                out['sent_hashtags'].append({'tag': tag, 'score': score})
        for _ in range(scnt):
            tag = st.qstr()
            score = st.u16()
            if tag:
                out['search_hashtags'].append({'tag': tag, 'score': score})
        bcnt = st.u32()
        for _ in range(bcnt):
            u = st.qstr()
            score = st.u16()
            if u:
                out['bots'].append({'username': u, 'score': score})
    except (EOFError, struct.error):
        pass
    return out


def extract_activity(acct: str, subkeys: dict, local_key: bytes):
    result = {}
    for name, fk in subkeys.items():
        payload = None
        for postfix in ('s', '0', '1'):
            p = os.path.join(acct, to_file_part(fk) + postfix)
            if os.path.isfile(p):
                tdf = read_tdf(p)
                if tdf:
                    st = QStream(tdf[1])
                    try:
                        blob = st.qba()
                    except EOFError:
                        blob = b''
                    if blob:
                        payload = decrypt_local(local_key, blob)
                    if payload is None:
                        try:
                            payload = decrypt_local(local_key, tdf[1])
                        except Exception:
                            payload = None
                    if payload:
                        break
        if not payload:
            continue
        try:
            if name == 'media_playback':
                result['media_playback'] = parse_playback(payload)
            elif name == 'search_suggestions':
                result['search_suggestions'] = parse_search_suggestions(payload)
            elif name == 'hashtags_bots':
                result['hashtags_bots'] = parse_hashtags_bots(payload)
        except Exception:
            continue
    return result


def write_activity(out_dir: str, activity: dict, ui, account_ids=None):
    if not activity:
        return
    act_dir = os.path.join(out_dir, 'activity')
    os.makedirs(act_dir, exist_ok=True)
    lines = []
    for acct_name, data in activity.items():
        uid = (account_ids or {}).get(acct_name)
        lines.append(tr('act_account',
                        name=f'{acct_name} (id={uid})' if uid else acct_name))
        sugg = data.get('search_suggestions', {})
        if sugg.get('top_peers'):
            lines.append('\n' + tr('act_top'))
            for p in sugg['top_peers']:
                who = p.get('username') or p.get('phone') or p['type']
                lines.append(f"  {p.get('name', '?')} [{p['type']} {p['id']}] @{who}"
                             f" rating={p.get('rating', 0)}")
        if sugg.get('recent_peers'):
            lines.append('\n' + tr('act_recent'))
            for p in sugg['recent_peers']:
                who = p.get('username') or p.get('phone') or p['type']
                lines.append(f"  {p.get('name', '?')} [{p['type']} {p['id']}] @{who}")
        hb = data.get('hashtags_bots', {})
        if hb.get('sent_hashtags'):
            lines.append('\n' + tr('act_sent_tags')
                         + ', '.join(f"{h['tag']}({h['score']})" for h in hb['sent_hashtags']))
        if hb.get('search_hashtags'):
            lines.append('\n' + tr('act_search_tags')
                         + ', '.join(f"{h['tag']}({h['score']})" for h in hb['search_hashtags']))
        if hb.get('bots'):
            lines.append('\n' + tr('act_bots')
                         + ', '.join(f"@{b['username']}({b['score']})" for b in hb['bots']))
        pb = data.get('media_playback')
        if pb:
            lines.append('\n' + tr('act_playback'))
            for m in pb:
                lines.append(f"  doc:{m['document_id']}  {m['position_ms'] / 1000:.1f}s")
        lines.append('')
    with open(os.path.join(act_dir, 'activity.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    with open(os.path.join(act_dir, 'activity.json'), 'w', encoding='utf-8') as f:
        json.dump(activity, f, ensure_ascii=False, indent=1)
    ui.log(tr('log_activity',
              p=sum(len(v.get('search_suggestions', {}).get('top_peers', []))
                    + len(v.get('search_suggestions', {}).get('recent_peers', []))
                    for v in activity.values()),
              v=sum(len(v.get('media_playback', [])) for v in activity.values())), 'ok')

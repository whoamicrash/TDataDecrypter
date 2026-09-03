import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile

from .activity import (decode_peer_id, parse_hashtags_bots,
                       parse_playback, parse_search_suggestions)
from .ayugram import dump_ayudata
from .binlog import key_kind, media_name, parse_binlog, xxh32
from .cache import merge_slice_run, parse_slice_value, slice_runs
from .constants import K_IN_SLICE, MAX_MERGE_BYTES
from .crypto import (create_local_key, decrypt_local, encrypt_local,
                     ige256_decrypt, ige256_encrypt, tgcrypto)
from .i18n import STR, tr
from .keys import extract_local_key, find_john, john_cmd, john_hash
from .media import (jpeg_sane, mp4_walk, sniff_media, trim_jpeg,
                    val_mp4, val_tgs)
from .texts import clean_dump, hump_check, is_keep, parse_self_user_id
from .videos import (ChunkStore, is_slice_parts, parse_slice_map,
                     walk_boxes_store)


def _mkbox(typ: bytes, payload: bytes = b'') -> bytes:
    return struct.pack('>I', 8 + len(payload)) + typ + payload


def selftest():
    import random
    fails = []

    def check(key, cond):
        name = tr(key)
        print(f"  [{'OK' if cond else 'FAIL'}] {name}", flush=True)
        if not cond:
            fails.append(name)

    print('== TDataDecrypter selftest ==')

    check('st_xxh32_empty', xxh32(b'') == 0x2CC5D05)
    check('st_xxh32_a', xxh32(b'a') == 0x550D7456)

    key, iv = os.urandom(32), os.urandom(32)
    data = os.urandom(160)
    enc = ige256_encrypt(data, key, iv)
    check('st_ige_rt', ige256_decrypt(enc, key, iv) == data)
    if tgcrypto is not None:
        check('st_ige_tgcrypto',
              ige256_encrypt(data, key, iv) == tgcrypto.ige256_encrypt(data, key, iv))

    lk = os.urandom(256)
    payload = b'hello tdata world' * 4
    check('st_decryptlocal_rt',
          decrypt_local(lk, encrypt_local(lk, payload)) == payload)
    check('st_decryptlocal_bad', decrypt_local(lk, b'\x00' * 48) is None)

    salt = os.urandom(32)
    check('st_createkey_det',
          create_local_key(b'', salt) == create_local_key(b'', salt))

    jpg = b'\xff\xd8\xff\xe0' + os.urandom(500) + b'\xff\xd9' + b'GARBAGE' * 10
    t = trim_jpeg(jpg)
    check('st_trim_garbage',
          t is not None and t.endswith(b'\xff\xd9') and len(t) == 506)
    check('st_trim_noeoi', trim_jpeg(b'\xff\xd8\xff' + b'x' * 100) is None)

    good_jpg = (b'\xff\xd8\xff\xe0' + struct.pack('>H', 16) + b'JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00'
                + b'\xff\xdb' + struct.pack('>H', 67) + b'\x00' * 65
                + b'\xff\xc0' + struct.pack('>H', 17) + b'\x08\x00\x20\x00\x20\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01'
                + b'\xff\xda' + struct.pack('>H', 12) + b'\x01\x00\x00\x3f\x00\x00' + b'\x7f' * 800 + b'\xff\xd9')
    junk_jpg = b'\xff\xd8\xff\xeb' + os.urandom(4096) + b'\xff\xd9'
    check('st_jpeg_ok', jpeg_sane(good_jpg))
    check('st_jpeg_junk', not jpeg_sane(junk_jpg))

    lottie = json.dumps({'v': '5.5.7', 'fr': 30, 'op': 60, 'layers': []}).encode()
    gz = gzip.compress(lottie)
    tgs = gz + b'JUNKTAIL'
    check('st_tgs_ok', val_tgs(tgs) == gz)
    check('st_tgs_bad', val_tgs(b'notgzip' * 5) is None)

    big_mdat_payload = b'\x00' * 64
    mdat64 = struct.pack('>I', 1) + b'mdat' + struct.pack('>Q', 16 + len(big_mdat_payload)) + big_mdat_payload
    mp4 = _mkbox(b'ftyp', b'isom' + struct.pack('>I', 0x200) + b'isomiso2avc1mp41')
    mp4 += _mkbox(b'moov', b'\x00' * 32)
    mp4 += mdat64
    boxes, end, ok = mp4_walk(mp4)
    check('st_mp4walk64',
          ok and [t for _, _, t in boxes] == [b'ftyp', b'moov', b'mdat'] and end == len(mp4))
    vok, why, trimmed = val_mp4(mp4 + b'\x00' * 8)
    check('st_valmp4_ok', vok and why == 'ok' and trimmed == mp4)
    vok2, why2, _ = val_mp4(mp4[:40])
    check('st_valmp4_trunc', not vok2)
    no_moov = _mkbox(b'ftyp', b'isom') + _mkbox(b'mdat', b'\x00' * 32)
    _, why3, _ = val_mp4(no_moov)
    check('st_valmp4_nomov', why3 == 'no-moov')

    store = ChunkStore()
    store.add(0, mp4[:64])
    store.add(64, mp4[64:])
    e2, boxes2 = walk_boxes_store(store, len(mp4))
    check('st_wbs', e2 == len(mp4) and len(boxes2) == 3)
    check('st_verify',
          store.verify(10, mp4[10:30]) is True and store.verify(10, b'ZZZZ') is False)

    part1, part2 = os.urandom(128 * 1024), os.urandom(64 * 1024)
    cmap = struct.pack('<I', 2) + struct.pack('<II', 0, len(part1)) + part1 \
        + struct.pack('<II', 128 * 1024, len(part2)) + part2
    parts, rem, complex_ = parse_slice_value(cmap)
    check('st_psv_complex',
          complex_ and parts[0] == (0, part1) and parts[1] == (128 * 1024, part2))
    m, r = parse_slice_map(cmap, K_IN_SLICE)
    check('st_psm_eq', m == dict(parts) and r == b'')
    plain = part1 + part2
    plain = part1 + part1
    m2, r2 = parse_slice_map(plain, K_IN_SLICE)
    check('st_psm_plain',
          m2 == {0: part1, 131072: part1} and r2 == b'')
    check('st_isp_plain', is_slice_parts(m2))
    check('st_isp_bad',
          not is_slice_parts({17: b'x' * 128}))

    keep_samples = ['SmartFox', 'BigLazyCat', 'blackbear', 'ZoomZoom',
                    'Привет, как дела', '@durov', 'https://t.me/durov',
                    'Cool Pack', 'A1B2C3D4E5F6.webm', '79001234567']
    drop_samples = ['GElFvCYHtEG', 'NlBLqXZ', 'xzjqwv', 'ASDFGHJKL']
    check('st_keep_human', all(is_keep(s) for s in keep_samples))
    check('st_keep_junk', not any(is_keep(s) for s in drop_samples))
    check('st_hump', hump_check('SmartFox') and not hump_check('GElFvCYHtEG'))

    check('st_sniff',
          sniff_media(b'\xff\xd8\xff\xe0' + b'\x00' * 32)[0] == 'jpg'
          and sniff_media(b'\x89PNG\r\n\x1a\n' + b'\x00' * 16)[0] == 'png'
          and sniff_media(b'RIFF\x24\x00\x00\x00WEBPVP8 ')[0] == 'webp'
          and sniff_media(b'OggS' + b'\x00' * 28)[0] == 'ogg'
          and sniff_media(mp4)[0] == 'mp4'
          and sniff_media(b'\x1aE\xdf\xa3' + b'\x00' * 12)[0] == 'webm'
          and sniff_media(gz)[0] == 'tgs')
    check('st_sniff_deep', sniff_media(b'JUNKJUNK' + jpg, deep=True)[0] == 'jpg')
    check('st_sniff_svg', sniff_media(b'<svg xmlns="http://www.w3.org/2000/svg">')[0] == 'svg')

    check('st_keykind',
          key_kind(0x0000000000000104) == 'document'
          and key_kind(0x0000000000000202) == 'document_thumb'
          and key_kind(0x00000100000000AB) == 'document_chunk'
          and key_kind(0x0000020000000003) == 'web_document'
          and key_kind(0x0000000012345678) == 'photo')
    check('st_mn_voice',
          media_name(0x104, 7123456789012345678, 3) == 'voice_7123456789012345678')
    check('st_mn_photo',
          media_name((ord("x") << 16) | 4, 5847634982736473920, 1) == 'photo_5847634982736473920_x')
    check('st_mn_video',
          media_name(0x00000100000000AB, (3785421258 << 32) | 0xDEAD, 5) == 'video_3785421258')

    ts_store = 1724000000
    rec = (bytes([1, 3]) + len(b'ogg-data').to_bytes(3, 'little')
           + bytes.fromhex('A1B2C3D4E5F607') + struct.pack('<I', 0x11223344)
           + struct.pack('<QQ', 0x104, 7123456789012345678)
           + struct.pack('<IIII', 7, 0, ts_store, 0))
    binlog = struct.pack('<IIII', 0x100, 1724000001, 0, 0) + rec
    ents = parse_binlog(binlog)
    e = ents.get((0x104, 7123456789012345678))
    check('st_binlog',
          e is not None and e[6] == ts_store and e[7] == 7 and e[3] == len(b'ogg-data'))

    check('st_peerid',
          decode_peer_id(0x0080000000000001 | 1) == ('user', 1)
          and decode_peer_id(0x0082000000000002) == ('channel', 2)
          and decode_peer_id(0x0000000100000002) == ('chat', 2))

    pb_data = struct.pack('>I', 2) + struct.pack('>Qq', 5847634982736473920, 123456) \
        + struct.pack('>Qq', 6111111111111111111, 65000)
    pb = parse_playback(pb_data)
    check('st_playback',
          len(pb) == 2 and pb[0]['document_id'] == 5847634982736473920
          and pb[0]['position_ms'] == 123456)

    def qstr(s):
        return struct.pack('>I', len(s)) + s
    hb_data = (struct.pack('>II', 1, 1) + qstr('#durov'.encode('utf-16-be'))
               + struct.pack('>H', 5)
               + qstr('#telegram'.encode('utf-16-be')) + struct.pack('>H', 3)
               + struct.pack('>I', 1) + qstr('BotFather'.encode('utf-16-be'))
               + struct.pack('>H', 2))
    hb = parse_hashtags_bots(hb_data)
    check('st_hashtags',
          hb['sent_hashtags'] == [{'tag': '#durov', 'score': 5}]
          and hb['search_hashtags'] == [{'tag': '#telegram', 'score': 3}]
          and hb['bots'] == [{'username': 'BotFather', 'score': 2}])

    def make_top_peers():
        out = struct.pack('>III', 1003008, 0, 1)
        out += struct.pack('>Q', 0x0080000000000001 | 1)
        out += struct.pack('>Q', 123456)
        out += struct.pack('>iiiQiQ', 100, 100, 2, 111, 0, 777)
        out += qstr('Павел'.encode('utf-16-be')) + qstr('Дуров'.encode('utf-16-be'))
        out += qstr('+79001234567'.encode('utf-16-be')) + qstr('durov'.encode('utf-16-be'))
        out += struct.pack('>Q', 42) + struct.pack('>I', 1724000000) \
            + struct.pack('>Iiii', 0, 1724000001, 1, -1)
        out += struct.pack('>Q', 99)
        return out
    sugg_data = (struct.pack('>I', len(make_top_peers())) + make_top_peers()
                 + struct.pack('>I', 0))
    sugg = parse_search_suggestions(sugg_data)
    check('st_sugg',
          len(sugg['top_peers']) == 1
          and sugg['top_peers'][0]['name'] == 'Павел Дуров'
          and sugg['top_peers'][0]['phone'] == '+79001234567'
          and sugg['top_peers'][0]['username'] == 'durov'
          and sugg['top_peers'][0]['rating'] == 99)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        salt = os.urandom(32)
        kdf = create_local_key(b'', salt)
        real_key = os.urandom(256)
        ke = encrypt_local(kdf, real_key)
        ie = encrypt_local(real_key, struct.pack('>i', 1))
        kd = (b'TDF$' + struct.pack('<i', 1003008)
              + qstr(salt) + qstr(ke) + qstr(ie))
        kd += hashlib.md5(kd[8:] + struct.pack('<i', len(kd) - 8)
                          + struct.pack('<i', 1003008) + b'TDF$').digest()
        with open(os.path.join(td, 'key_datas'), 'wb') as f:
            f.write(kd)
        jh = john_hash(td)
        check('st_john', jh is not None and re.fullmatch(
                  r'\$telegram\$2\*100000\*[0-9a-f]{64}\*[0-9a-f]+', jh) is not None
              and bytes.fromhex(jh.split('*')[3]) == ke)
        lk3, msg3 = extract_local_key(td)
        check('st_extractkey', lk3 == real_key)

        kdf_p = create_local_key(b'1234', salt)
        ke_p = encrypt_local(kdf_p, real_key)
        kd_p = (b'TDF$' + struct.pack('<i', 1003008)
                + qstr(salt) + qstr(ke_p) + qstr(ie))
        kd_p += hashlib.md5(kd_p[8:] + struct.pack('<i', len(kd_p) - 8)
                            + struct.pack('<i', 1003008) + b'TDF$').digest()
        with open(os.path.join(td, 'key_datas'), 'wb') as f:
            f.write(kd_p)
        lk4, _msg4 = extract_local_key(td, b'1234')
        lk5, msg5 = extract_local_key(td, b'9999')
        lk6, msg6 = extract_local_key(td)
        check('st_johnwrong',
              lk4 == real_key and lk5 is None and lk6 is None
              and tr('key_wrong_pass') in msg5
              and tr('key_john_hint') in msg6)

    check('st_johncmd',
          john_cmd('/usr/bin/john', '/p', '/s', '/h') == [
              '/usr/bin/john', '--format=telegram', '--pot=/p',
              '--session=/s', '/h']
          and john_cmd('john', 'p', 's', 'h', wordlist='w.lst',
                       rules=True) == [
              'john', '--format=telegram', '--pot=p', '--session=s',
              '--wordlist=w.lst', '--rules', 'h']
          and john_cmd('john', 'p', 's', 'h', mask='?d?d?d?d') == [
              'john', '--format=telegram', '--pot=p', '--session=s',
              '--mask=?d?d?d?d', 'h'])
    jf = find_john()
    check('st_johnfind', jf is None or os.path.isfile(jf))

    class _UiStub:
        def __init__(self):
            self.msgs = []

        def log(self, msg, level='info'):
            self.msgs.append(msg)

    def _mk_part(n):
        return b'\xff\xff\xff\xff' + os.urandom(n)

    tmpd = tempfile.mkdtemp(prefix='tdsrun_')
    try:
        ent = ('AB0123456789AB', 0, 0, 90, 'AB0123456789AB', 0, 1, 2)
        lo = 15233144265675243766
        items = [(lo, _mk_part(86), ent),
                 (lo + (1 << 40) + 12345, _mk_part(18), ent),
                 (lo + (1 << 40) + 12345 + (1 << 44), _mk_part(2), ent)]
        runs = slice_runs(items)
        check('st_sliceruns', [len(r) for r in runs] == [1, 1, 1])
        res = [merge_slice_run(0x14A39, r, tmpd, _UiStub()) for r in runs]
        names = sorted(os.listdir(tmpd))
        check('st_slicemerge',
              all(r is not None for r in res) and len(names) == 3
              and all(n.startswith('photo_') for n in names))
        seq = [(5, _mk_part(6), ent), (6, _mk_part(6), ent),
               (8, _mk_part(6), ent)]
        check('st_slicerun_seq', [len(r) for r in slice_runs(seq)] == [3])
        r2 = merge_slice_run(0x14A39, seq, tmpd, _UiStub())
        check('st_slicemerge_seq',
              r2 is not None and r2[1] == 3 * K_IN_SLICE + 10 and r2[2] == 30)
        stub = _UiStub()
        huge = struct.pack('<I', 1) + struct.pack('<II', 0xFFFFFFFF, 4) + b'abcd'
        r3 = merge_slice_run(0x14A39, [(7, huge, ent)], tmpd, stub)
        check('st_slicehuge',
              r3 is None and len(stub.msgs) == 1
              and tr('merge_huge', name='photo_7',
                     max=MAX_MERGE_BYTES // (1024 * 1024)) in stub.msgs[0])
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    mod = struct.pack('<II', 0x1F466157, 0) + struct.pack('<Q', 493509432)
    mod2 = struct.pack('<II', 0x1F466157, 0) + struct.pack('<Q', 7942237000)
    oldu = (struct.pack('<II', 0x1F466157, 0) + struct.pack('<I', 493509432)
            + struct.pack('<I', 6) + b'Vasya')
    check('st_selfid',
          parse_self_user_id(mod) == 493509432
          and parse_self_user_id(mod2) == 7942237000
          and parse_self_user_id(b'\x00' * 8) is None)
    check('st_selfid_old', parse_self_user_id(oldu) == 493509432)

    class _UiNil:
        def log(self, *a, **k):
            pass

    tmpa = tempfile.mkdtemp(prefix='tdayu_')
    try:
        adb = os.path.join(tmpa, 'ayudata.db')
        con = sqlite3.connect(adb)
        con.execute('CREATE TABLE DeletedMessage (dialogId INTEGER, '
                    'fromId INTEGER, messageId INTEGER, date INTEGER, '
                    'text TEXT, mediaPath TEXT)')
        for row in ((1, 1, 5, 100, 'e', None), (1, 1, 2, 300, 'a', None),
                    (2, 1, 1, 200, 'x', None)):
            con.execute('INSERT INTO DeletedMessage VALUES (?,?,?,?,?,?)',
                        row)
        con.commit()
        con.close()
        dump_ayudata(tmpa, tmpa, _UiNil())
        with open(os.path.join(tmpa, 'ayugram', 'deleted_messages.txt'),
                  encoding='utf-8') as f:
            dc = f.read()
        check('st_ayusort',
              0 <= dc.find('msg=2 date') < dc.find('msg=5 date')
              < dc.find('msg=1 date'))
    finally:
        shutil.rmtree(tmpa, ignore_errors=True)

    tmpg = tempfile.mkdtemp(prefix='tdgrp_')
    try:
        dp = os.path.join(tmpg, 'dump.txt')
        with open(dp, 'w', encoding='utf-8') as f:
            f.write('[self@300] Иван Петров\n[self@100] Пупкин Адрес\n'
                    '[settings#1] настройка включена\n')
        op = os.path.join(tmpg, 'messages.txt')
        clean_dump(dp, op, None)
        with open(op, encoding='utf-8') as f:
            gc = f.read()
        check('st_groupsort',
              0 <= gc.find('id=100') < gc.find('id=300')
              < gc.find('настройка'))
    finally:
        shutil.rmtree(tmpg, ignore_errors=True)

    def _fmt_keys(s):
        return sorted(re.findall(r'\{(\w+)\}', s))
    check('st_lang_tables', set(STR['ru']) == set(STR['en']) and all(
        _fmt_keys(STR['ru'][k]) == _fmt_keys(STR['en'][k]) for k in STR['ru']))

    print(f"\n{tr('st_all_ok') if not fails else tr('st_failed', n=len(fails), fails=fails)}")
    return not fails

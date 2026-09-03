import json
import os
import re
import shutil
import time
import traceback
from collections import defaultdict

from .activity import extract_activity, write_activity
from .ayugram import dump_ayudata
from .cache import iter_place_files, process_cache_db
from .classify import classify_blob, extract_embedded, make_dedupe
from .constants import APP_TITLE
from .crypto import create_legacy_local_key, decrypt_local
from .exceptions import CancelledError
from .i18n import tr
from .keys import extract_local_key
from .media import sniff_media
from .tdf import QStream, parse_map, read_tdf, to_file_part
from .texts import clean_dump, extract_texts, parse_self_user_id
from .ui import ConsoleUI, Options
from .videos import rebuild_videos


def locate_tdata(path: str):
    try:
        if any(f.startswith('key_dat') for f in os.listdir(path)):
            return path
    except OSError:
        return None
    for fn in sorted(os.listdir(path)):
        sub = os.path.join(path, fn)
        if os.path.isdir(sub) and fn.lower().startswith('tdata'):
            try:
                if any(f.startswith('key_dat') for f in os.listdir(sub)):
                    return sub
            except OSError:
                continue
    return None


def walk_tdf(path: str, local_key: bytes, ctx):
    tdf = read_tdf(path)
    if not tdf:
        return
    _, data, _ = tdf
    st = QStream(data)
    try:
        first = st.qba()
    except EOFError:
        return
    keys = []
    if len(first) == 32:
        keys.append(('legacy-settings', create_legacy_local_key(b'', first)))
    keys.append(('local', local_key))
    pos = st.p
    if len(first) != 32:
        st = QStream(data)
    idx = 0
    while True:
        try:
            blob = st.qba()
        except EOFError:
            break
        idx += 1
        if not blob or len(blob) <= 16:
            continue
        for kname, k in keys:
            payload = decrypt_local(k, blob)
            if payload is not None:
                ctx.on_decrypted(path, kname, idx, payload)
                break


class TDataDecrypter:

    def __init__(self, tdata_path: str, out_dir: str, passcode: str = '',
                 opts: Options = None, ui: ConsoleUI = None):
        self.tdata_arg = tdata_path
        self.out = os.path.abspath(out_dir)
        self.passcode = (passcode or '').encode('utf-8')
        self.opts = opts or Options()
        self.ui = ui or ConsoleUI()
        self.stats = defaultdict(int)
        self.report = []
        self.local_key = None
        self.tdata = None
        self.text_count = 0
        self.embedded_media = 0
        self.media_index = []
        self.activity = {}
        self.account_ids = {}
        self.dedupe = make_dedupe(self.stats)
        self._stage_no = 0
        os.makedirs(self.out, exist_ok=True)
        self.msg_path = os.path.join(self.out, 'messages_dump.txt')
        open(self.msg_path, 'w', encoding='utf-8').close()
        self.staging = os.path.join(self.out, '.staging')


    def log(self, msg, level='info'):
        self.ui.log(msg, level)
        self.report.append(f'[{ {"ok": "+", "warn": "!", "err": "X"}.get(level, "i") }] {msg}')

    def check_cancel(self):
        if getattr(self.ui, 'cancelled', False):
            raise CancelledError()

    def stage(self, name):
        self._stage_no += 1
        self.ui.stage(tr('stage_fmt', n=self._stage_no, name=name))
        self.report.append(tr('rep_stage_fmt', n=self._stage_no, name=name))

    def _prog(self, a, b, frac, note=''):
        try:
            self.ui.progress(min(a + (b - a) * max(0.0, min(1.0, frac)), 1.0), note)
        except Exception:
            pass


    def on_decrypted(self, path, keyname, idx, payload):
        base = os.path.basename(path)
        try:
            texts = extract_texts(payload)
        except Exception as e:
            self.log(tr('texts_fail', src=f'{base}#{idx}', e=e), 'warn')
            texts = []
        if texts:
            with open(self.msg_path, 'a', encoding='utf-8') as f:
                for t in texts:
                    f.write(f'[{base}#{idx}] {t}\n')
            self.text_count += len(texts)
        try:
            ext, off = sniff_media(payload, deep=True)
            if ext:
                clean = payload[off:] if off else payload
                dest = classify_blob(clean, f'{base}_{idx}.{ext}', self.out,
                                     self.dedupe, self.stats)
                if dest:
                    self.embedded_media += 1
        except Exception as e:
            self.log(tr('deep_fail', src=f'{base}#{idx}', e=e), 'warn')


    def process_account_dir(self, acct):
        drafts, self_data, subkeys, errs = [], None, {}, []
        for fn in os.listdir(acct):
            if fn.lower().startswith('map'):
                d, s, sk, e = parse_map(os.path.join(acct, fn), self.local_key)
                if d:
                    drafts = d
                self_data = self_data or s
                subkeys.update(sk)
                errs += e
        for e in errs:
            self.log(f"[!] {e}", 'warn')
        acct_base = os.path.basename(acct)
        uid = parse_self_user_id(self_data) if self_data else None
        self.account_ids[acct_base] = uid
        self.log(tr('account_id', dir=acct_base,
                    id=str(uid) if uid is not None else '?'),
                 'ok' if uid is not None else 'info')
        if subkeys:
            try:
                act = extract_activity(acct, subkeys, self.local_key)
                if act:
                    self.activity[acct_base] = act
            except Exception as e:
                self.log(tr('activity_err', name=acct_base, e=e), 'warn')
        if self_data:
            try:
                texts = extract_texts(self_data)
            except Exception:
                texts = []
            stag = f'self@{uid}' if uid is not None else f'self@{acct_base}'
            with open(self.msg_path, 'a', encoding='utf-8') as f:
                for t in texts:
                    f.write(f'[{stag}] {t}\n')
            self.text_count += len(texts)
            self.log(tr('self_serialized', n=len(texts)), 'ok')
        if drafts:
            self.log(tr('drafts_found', n=len(drafts)))
        for pid, fk in drafts:
            for postfix in ('s', '0', '1'):
                df = os.path.join(acct, to_file_part(fk) + postfix)
                if os.path.isfile(df):
                    walk_tdf(df, self.local_key, self)
                    break
        for fn in os.listdir(acct):
            full = os.path.join(acct, fn)
            if os.path.isfile(full) and read_tdf(full) and not fn.lower().startswith('map'):
                if not any(fn.startswith(to_file_part(fk)) for _, fk in drafts):
                    walk_tdf(full, self.local_key, self)


    def run(self):
        self._t0 = time.time()
        t0 = self._t0
        try:
            return self._run_inner()
        except CancelledError:
            self.log(tr('cancelled_by_user'), 'warn')
            self._write_report(time.time() - t0, ok=False)
            return False
        except Exception as e:
            self.log(tr('critical_err', e=e), 'err')
            for line in traceback.format_exc().splitlines()[-8:]:
                self.report.append('    ' + line)
            self._write_report(time.time() - t0, ok=False)
            return False

    def _run_inner(self):
        o = self.opts
        out = self.out

        self.stage(tr('st_search'))
        self._prog(0.0, 0.02, 1)
        if not os.path.isdir(self.tdata_arg):
            self.log(tr('path_not_found', path=self.tdata_arg), 'err')
            return False
        self.tdata = locate_tdata(self.tdata_arg)
        if not self.tdata:
            self.log(tr('tdata_not_found'), 'err')
            return False
        if self.tdata != os.path.abspath(self.tdata_arg):
            self.log(tr('tdata_found', path=self.tdata))
        accounts = [f for f in os.listdir(self.tdata)
                    if os.path.isdir(os.path.join(self.tdata, f))
                    and re.fullmatch(r'[0-9A-F]{16}', f)]
        user_dbs = [f for f in os.listdir(self.tdata)
                    if os.path.isdir(os.path.join(self.tdata, f))
                    and f.startswith('user_')]
        self.log(tr('accounts_found', a=len(accounts), c=len(user_dbs)))

        self.stage(tr('st_key'))
        self._prog(0.02, 0.05, 0.5)
        self.local_key, msg = extract_local_key(self.tdata, self.passcode)
        if self.local_key is None:
            self.log(msg, 'err')
            self._prog(0.02, 0.05, 1)
            return False
        self.log(msg, 'ok')
        self._prog(0.02, 0.05, 1)
        self.check_cancel()

        self.stage(tr('st_ayu'))
        try:
            dump_ayudata(self.tdata, out, self.ui)
        except Exception as e:
            self.log(tr('ayu_err', e=e), 'warn')
        self._prog(0.05, 0.06, 1)
        self.check_cancel()

        self.stage(tr('st_settings'))
        for fn in os.listdir(self.tdata):
            full = os.path.join(self.tdata, fn)
            if not os.path.isfile(full):
                continue
            if re.fullmatch(r'key_data\S*', fn):
                continue
            if fn.startswith(('settings', 'usertag')):
                walk_tdf(full, self.local_key, self)
                self.log(tr('processed_file', fn=fn))
            self._prog(0.06, 0.11, 0.5)
        for fn in accounts:
            self.process_account_dir(os.path.join(self.tdata, fn))
            self.check_cancel()
        if accounts:
            ids_parts = [
                str(self.account_ids[f]) if self.account_ids.get(f) is not None
                else f'{f} (?)' for f in accounts]
            self.log(tr('accounts_ids', ids=', '.join(ids_parts)))
        self.log(tr('texts_dumped', n=self.text_count, m=self.embedded_media))
        self._prog(0.06, 0.16, 1)

        self.stage(tr('st_cache'))
        self._prog(0.16, 0.17, 0.2)
        grand_total = 0
        db_dirs = []
        for fn in user_dbs:
            for sub in ('cache', 'media_cache'):
                subpath = os.path.join(self.tdata, fn, sub)
                if os.path.isdir(subpath):
                    n = sum(len(iter_place_files(r)) for r, _, _ in os.walk(subpath))
                    db_dirs.append((subpath, 'media_cache' in sub, n))
                    grand_total += n
        done = [0]

        def tick():
            self.check_cancel()
            done[0] += 1
            if grand_total:
                self._prog(0.17, 0.60, done[0] / grand_total,
                           tr('prog_cache', d=done[0], t=grand_total))

        for subpath, is_media, _n in db_dirs:
            rel = os.path.relpath(subpath, self.tdata)
            saved, idx = process_cache_db(subpath, self.local_key, self.staging,
                                          self.ui, self.stats, is_media, tick=tick)
            self.media_index.extend(idx)
            self.log(tr('cache_done', rel=rel, n=saved), 'ok')
        if grand_total == 0:
            self.log(tr('no_cache'))
        self._prog(0.16, 0.60, 1)
        self.check_cancel()

        used_recon = set()
        if o.sort_media:
            self.stage(tr('st_sort'))
            cache_staging = os.path.join(self.staging, 'cache')
            files = []
            if os.path.isdir(cache_staging):
                for root, dirs, fs in os.walk(cache_staging):
                    files += [os.path.join(root, f) for f in fs]
            for i, path in enumerate(files):
                if i % 64 == 0:
                    self.check_cancel()
                    self._prog(0.60, 0.78, (i + 1) / max(len(files), 1),
                               tr('prog_media', d=i + 1, t=len(files)))
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read()
                    classify_blob(data, os.path.basename(path), out,
                                  self.dedupe, self.stats)
                except OSError:
                    pass
            self.log(tr('staging_files', n=len(files),
                        d=self.stats["dupes_dropped"]))
            self._prog(0.60, 0.78, 1)
        else:
            self.stage(tr('st_move'))
            for src, dst in ((os.path.join(self.staging, 'cache'), os.path.join(out, 'cache')),
                             (os.path.join(self.staging, 'media_cache'),
                              os.path.join(out, 'media_cache'))):
                if os.path.isdir(src):
                    shutil.move(src, dst)
            self._prog(0.60, 0.78, 1)
        self.check_cancel()

        mc_staging = os.path.join(self.staging, 'media_cache')
        if o.merge_videos and os.path.isdir(mc_staging):
            self.stage(tr('st_merge'))
            try:
                used_recon = rebuild_videos(
                    mc_staging,
                    os.path.join(out, 'videos'),
                    os.path.join(out, 'videos', 'partial'),
                    self.ui, self.stats, self.dedupe,
                    cancel_check=self.check_cancel)
            except CancelledError:
                raise
            except Exception as e:
                self.log(tr('merge_videos_fail', e=e), 'warn')
                used_recon = set()
            self._prog(0.78, 0.92, 1)
            self.check_cancel()
        else:
            self._prog(0.78, 0.92, 1)

        if o.sort_media and os.path.isdir(mc_staging):
            self.stage(tr('st_classify'))
            files = []
            for root, dirs, fs in os.walk(mc_staging):
                files += [os.path.join(root, f) for f in fs]
            kept = 0
            embedded = 0
            for i, path in enumerate(files):
                if i % 32 == 0:
                    self.check_cancel()
                    self._prog(0.92, 0.96, (i + 1) / max(len(files), 1))
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read()
                except OSError:
                    continue
                if path in used_recon:
                    if extract_embedded(data, os.path.basename(path).rsplit('.', 1)[0],
                                        out, self.dedupe, self.stats):
                        embedded += 1
                    continue
                if classify_blob(data, os.path.basename(path), out,
                                 self.dedupe, self.stats):
                    kept += 1
            self.log(tr('mc_classified', k=kept, e=embedded))
            self._prog(0.92, 0.96, 1)

        self.stage(tr('st_texts'))
        texts_dir = os.path.join(out, 'texts')
        os.makedirs(texts_dir, exist_ok=True)
        if o.clean_texts:
            try:
                kept_n, dropped_n = clean_dump(self.msg_path,
                                               os.path.join(texts_dir, 'messages.txt'),
                                               self.ui)
                self.log(tr('texts_cleaned', k=kept_n, d=dropped_n), 'ok')
            except Exception as e:
                self.log(tr('clean_fail', e=e), 'warn')
                o.clean_texts = False
        if o.clean_texts and o.raw_dump:
            shutil.move(self.msg_path, os.path.join(texts_dir, 'raw_dump.txt'))
        elif o.clean_texts:
            try:
                os.remove(self.msg_path)
            except OSError:
                pass
        else:
            pass
        self._prog(0.96, 0.99, 1)
        self.check_cancel()

        self.stage(tr('st_index'))
        try:
            self._write_media_index()
        except Exception as e:
            self.log(tr('index_fail', e=e), 'warn')
        if self.activity:
            try:
                write_activity(out, self.activity, self.ui, self.account_ids)
            except Exception as e:
                self.log(tr('activity_fail', e=e), 'warn')
        if os.path.isdir(self.staging) and not o.keep_staging:
            shutil.rmtree(self.staging, ignore_errors=True)
        self._prog(0.99, 1.0, 1)
        self._write_report(time.time() - self._t0, ok=True)
        return True

    def _write_media_index(self):
        if not self.media_index:
            return
        by_stem = {}
        for e in self.media_index:
            by_stem.setdefault(e['stem'], e)
        matched = 0
        with open(os.path.join(self.out, 'media_index.jsonl'), 'w',
                  encoding='utf-8') as fx:
            for sub in ('photos', 'videos', 'stickers', 'voice', 'files'):
                top = os.path.join(self.out, sub)
                if not os.path.isdir(top):
                    continue
                for root, dirs, fs in os.walk(top):
                    for fn in fs:
                        stem = fn.rsplit('.', 1)[0]
                        m = re.search(r'_(\d+)$', stem)
                        entry = by_stem.get(stem)
                        if entry is None and m and m.group(1).isdigit():
                            entry = by_stem.get(stem[:m.start()])
                        if entry is None:
                            continue
                        rec = dict(entry)
                        rec['file'] = os.path.relpath(os.path.join(root, fn), self.out)
                        ts = rec.get('stored') or 0
                        if 631152000 < ts < 2147483647:
                            try:
                                os.utime(os.path.join(root, fn), (ts, ts))
                                rec['mtime_set'] = ts
                            except OSError:
                                pass
                        rec.pop('stem', None)
                        fx.write(json.dumps(rec, ensure_ascii=False) + '\n')
                        matched += 1
        if matched:
            self.log(tr('index_written', n=matched), 'ok')


    def _stats_lines(self):
        s = self.stats
        lines = [
            tr('stats_photos', n=s.get('photos', 0), p=s.get('photos_partial', 0)),
            tr('stats_videos', n=s.get('videos', 0)),
            tr('stats_tgs', n=s.get('stickers_tgs', 0)),
            tr('stats_webp', n=s.get('stickers_webp', 0)),
            tr('stats_webm', n=s.get('stickers_webm', 0)),
            tr('stats_voice', n=s.get('voice', 0)),
            tr('stats_files',
               n=sum(v for k, v in s.items() if k.startswith('file_'))),
            tr('stats_junk',
               n=s.get('junk_unknown', 0) + s.get('classify_errors', 0)),
            tr('stats_broken',
               n=sum(v for k, v in s.items() if k.startswith('broken_'))),
            tr('stats_mp4_nomov', n=s.get('mp4_no-moov', 0)),
            tr('stats_mp4_trunc',
               n=s.get('mp4_truncated', 0) + s.get('mp4_garbage-tail', 0)),
            tr('stats_dupes', n=s.get('dupes_dropped', 0)),
            tr('stats_recon', n=s.get('recon_headers', 0),
               s=s.get('recon_slices_used', 0)),
            tr('stats_embedded', n=self.embedded_media),
            tr('stats_texts', n=self.text_count),
        ]
        return lines

    def _write_report(self, elapsed: float, ok: bool):
        status = tr('rep_ok') if ok else tr('rep_fail')
        head = [tr('rep_title', app=APP_TITLE),
                tr('rep_status', s=status),
                f'tdata: {self.tdata or self.tdata_arg}',
                tr('rep_out', p=self.out),
                tr('rep_time', t=f'{elapsed:.1f}'),
                '=' * 60]
        tail = ['', '=' * 60, tr('rep_total')] + self._stats_lines()
        with open(os.path.join(self.out, 'report.txt'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(head + self.report + tail))
        if ok:
            self.ui.stage(tr('st_summary'))
            for line in self._stats_lines():
                self.ui.log(line)
            self.ui.log(tr('done_out', out=self.out), 'ok')

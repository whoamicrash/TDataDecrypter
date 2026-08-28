import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import threading
import time
import traceback
import zlib
from collections import defaultdict

APP_TITLE = 'TDataDecrypter'

CFG_PATH = os.path.join(os.path.expanduser('~'), '.tdatadecrypter.json')

STR = {
    'ru': {
        'pycryptodome_missing': '[!] Нужен pycryptodome:  pip install pycryptodome',
        'key_missing': 'файл ключа (key_datass / key_datas0 / key_datas1) не найден',
        'key_not_tdf': '{name}: не TDF-файл',
        'key_parse_fail': '{name}: не удалось разобрать salt/keyEncrypted/infoEncrypted',
        'key_bad_salt': 'неожиданный размер соли: {n} (нужно 32)',
        'key_info_ok': ', info проверена (аккаунтов: {n})',
        'key_ok': 'LocalKey извлечён из {name} (режим: {kind}, версия tdata: {version}{note})',
        'key_wrong_pass': 'не удалось расшифровать keyEncrypted — неверный локальный пароль?',
        'key_john_hint': ' (хеш для брутфорса: --john)',
        'key_no_decrypt': 'не удалось расшифровать keyEncrypted (ни modern, ни legacy){hint}',
        'map_not_tdf': '{name}: не TDF',
        'map_bad_struct': '{name}: структура map не распознана',
        'map_not_decrypted': '{name}: map не расшифрована',
        'map_truncated': '{name}: map оборвалась (частично прочитана)',
        'act_account': '=== Аккаунт {name} ===',
        'act_top': '-- Часто открываемые (top peers):',
        'act_recent': '-- Недавние (recent peers / поиск):',
        'act_sent_tags': '-- Отправленные хештеги: ',
        'act_search_tags': '-- Искали хештеги: ',
        'act_bots': '-- Недавние боты: ',
        'act_playback': '-- Позиции воспроизведения (на какой секунде остановился):',
        'log_activity': '[+] активность: activity/activity.txt + activity.json (пиров: {p}, позиций видео: {v})',
        'src_self': 'ПРОФИЛЬ (selfSerialized: имя/телефон/username)',
        'src_settings': 'НАСТРОЙКИ (settingss)',
        'src_usertag': 'ЮЗЕРТЕГ (usertag)',
        'src_account': 'АККАУНТ {base}',
        'src_other': 'ИСТОЧНИК: {tag}',
        'texts_title': 'ТЕКСТЫ, ИЗВЛЕЧЁННЫЕ ИЗ TDATA',
        'texts_note': 'Источники: map-файлы аккаунтов (черновики, selfSerialized, названия\nстикерпаков), settingss (настройки), usertag. История переписки в\ntdata НЕ хранится — только на серверах Telegram. Мусор отфильтрован\nавтоматически (CamelCase-анализ + биграммы EN/RU).',
        'texts_group': '--- {title} ({n} строк) ---',
        'ayu_copy_fail': '[!] ayudata.db не скопирован: {e}',
        'ayu_dumped': '[+] AyuGram ayudata.db: удалённых сообщений: {d}, историй правок: {e} (см. ayugram/)',
        'ayu_read_fail': '[!] ayudata.db не прочитан: {e}',
        'ayu_err': '[!] ayudata: {e}',
        'binlog_ok': '[+] binlog разобран: {rel} ({n} записей)',
        'binlog_fail': '[!] binlog не прочитан: {e}',
        'checksum_fail': '[!] checksum не сошёлся: {place} (всё равно сохраняю)',
        'merged_holes': '[~] {name}: склеен с пропусками ({filled}/{total} байт) — слайсы в кэше неполные',
        'merge_fail': '[!] склейка слайсов {high}... не удалась: {e}',
        'parse_skip': '[~] разбор {name} пропущен: {e}',
        'no_headers': '[i] видео-заголовков в media_cache не найдено — склеивать нечего',
        'headers_merged': '[i] слито дублирующихся заголовков: {n}',
        'recon_stats': '[i] видео с заголовками: {n}, слайсов-кандидатов: {m}',
        'mode_verified': 'VERIFIED ({kb} КБ совпало)',
        'mode_assumed': 'ASSUMED (полный 8МБ слот)',
        'mode_assumed_tail': 'ASSUMED-TAIL (исход {pct}%)',
        'slice_assign': '    {name}: слайс {k} <- {file}: {mode}',
        'status_partial': 'PARTIAL {f}/{t} МБ ({p}%)',
        'status_fragment': 'FRAGMENT {f}/{t} МБ ({p}%, без moov)',
        'assembly_fail': '[!] сборка {name} не удалась: {e}',
        'unassigned': '[i] нераспределённых слайсов: {n} (хозяина не найдено)',
        'stage_fmt': 'Этап {n}: {name}',
        'rep_stage_fmt': '\n=== Этап {n}: {name} ===',
        'st_search': 'Поиск tdata',
        'st_key': 'Извлечение LocalKey',
        'st_ayu': 'AyuGram ayudata.db',
        'st_settings': 'Настройки, usertag, map-файлы аккаунтов, черновики',
        'st_cache': 'Кэш-базы user_*',
        'st_sort': 'Валидация и сортировка медиа',
        'st_move': 'Перенос кэшей как есть',
        'st_merge': 'Склейка видео из слайсов media_cache',
        'st_classify': 'Классификация остальных файлов media_cache',
        'st_texts': 'Тексты: чистка дампа от мусора',
        'st_index': 'Индекс медиа и уборка',
        'st_summary': 'Итог',
        'cancelled_by_user': 'ОТМЕНЕНО пользователем',
        'critical_err': 'КРИТИЧЕСКАЯ ОШИБКА: {e}',
        'path_not_found': 'путь не найден: {path}',
        'tdata_not_found': 'не нашёл папку с key_datass/key_datas* (это точно tdata?)',
        'tdata_found': 'tdata найдена: {path}',
        'accounts_found': 'аккаунтов: {a}, кэш-баз (user_*): {c}',
        'prog_cache': 'кэш: {d}/{t}',
        'prog_media': 'медиа: {d}/{t}',
        'processed_file': 'обработан {fn}',
        'texts_dumped': 'текстов в сырой дамп: {n}, встроенных медиа из TDF: {m}',
        'cache_done': 'кэш {rel}: извлечено блобов: {n}',
        'no_cache': 'кэш-базы не найдены (или пусты)',
        'staging_files': 'файлов в кэше-стейджинге: {n} (дубли убраны: {d})',
        'merge_videos_fail': '[!] склейка видео не удалась ({e}) — пропускаю, остальное не пострадало',
        'mc_classified': 'из media_cache классифицировано ещё: {k}, встроенных медиа вынуто: {e}',
        'texts_cleaned': 'человеческих строк: {k}, мусора отсеяно: {d}',
        'clean_fail': '[!] чистка текстов не удалась: {e} (сохраняю сырой дамп)',
        'index_fail': '[!] индекс медиа не записан: {e}',
        'activity_fail': '[!] активность не записана: {e}',
        'activity_err': '[!] активность ({name}): {e}',
        'index_written': '[+] media_index.jsonl: {n} файлов с file_id/dc/временем (mtime восстановлен по времени кэширования)',
        'texts_fail': '[!] тексты из {src}: {e}',
        'deep_fail': '[!] deep-медиа из {src}: {e}',
        'self_serialized': '[+] selfSerialized: {n} строк (имя/телефон/username)',
        'drafts_found': '[+] найдено черновиков: {n}',
        'stats_photos': 'фото:            {n} (+{p} обрезанных)',
        'stats_videos': 'видео:           {n} (+partial см. videos/partial)',
        'stats_tgs': 'стикеры tgs:     {n}',
        'stats_webp': 'стикеры webp:    {n}',
        'stats_webm': 'стикеры webm:    {n}',
        'stats_voice': 'голос (ogg):     {n}',
        'stats_files': 'прочие файлы:    {n}',
        'stats_junk': 'мусора отброшено: {n}',
        'stats_broken': 'битых jpg/png/webp/tgs/ogg: {n}',
        'stats_mp4_nomov': 'mp4 без moov (слайсы/фрагменты): {n}',
        'stats_mp4_trunc': 'mp4 обрезанных:  {n}',
        'stats_dupes': 'дубликатов убрано (SHA256): {n}',
        'stats_recon': 'видео-заголовков склеено: {n} (слайсов использовано: {s})',
        'stats_embedded': 'встроенных медиа из TDF: {n}',
        'stats_texts': 'текстов всего (raw): {n}',
        'rep_ok': 'УСПЕХ',
        'rep_fail': 'ПРЕРВАНО/ОШИБКА',
        'rep_title': '{app} — отчёт',
        'rep_status': 'Статус: {s}',
        'rep_out': 'Вывод: {p}',
        'rep_time': 'Время: {t} c',
        'rep_total': 'ИТОГО:',
        'done_out': 'Готово. Вывод: {out}',
        'st_all_ok': 'ВСЕ ТЕСТЫ ПРОЙДЕНЫ',
        'st_failed': 'ПРОВАЛЕНО: {n}: {fails}',
        'st_xxh32_empty': 'xxh32("") == 0x2CC5D05',
        'st_xxh32_a': 'xxh32("a") == 0x550D7456',
        'st_ige_rt': 'IGE roundtrip',
        'st_ige_tgcrypto': 'IGE == tgcrypto',
        'st_decryptlocal_rt': 'DecryptLocal roundtrip',
        'st_decryptlocal_bad': 'DecryptLocal портит битые',
        'st_createkey_det': 'CreateLocalKey детерминизм',
        'st_trim_garbage': 'trim_jpeg режет мусор после EOI',
        'st_trim_noeoi': 'trim_jpeg без EOI -> None',
        'st_jpeg_ok': 'jpeg_sane принимает структурный JPEG',
        'st_jpeg_junk': 'jpeg_sane режет ложный SOI из случайных байтов',
        'st_tgs_ok': 'val_tgs принимает Lottie и триммит хвост',
        'st_tgs_bad': 'val_tgs отвергает не-gzip',
        'st_mp4walk64': 'mp4_walk: 64-битный mdat + moov, структура цела',
        'st_valmp4_ok': 'val_mp4: ok + тримминг мелкого хвоста',
        'st_valmp4_trunc': 'val_mp4: обрезанность ловится',
        'st_valmp4_nomov': 'val_mp4: no-moov (слайс-фрагмент)',
        'st_wbs': 'walk_boxes_store по кускам == mp4_walk',
        'st_verify': 'ChunkStore.verify сверяет байты',
        'st_psv_complex': 'parse_slice_value: complex-карта',
        'st_psm_eq': 'parse_slice_map == parse_slice_value (complex)',
        'st_psm_plain': 'parse_slice_map: plain-слайс 256К',
        'st_isp_plain': 'is_slice_parts: plain 256К = да',
        'st_isp_bad': 'is_slice_parts: complex с кривыми оффсетами = нет',
        'st_keep_human': 'is_keep: человеческое остаётся',
        'st_keep_junk': 'is_keep: мусор отсеивается',
        'st_hump': 'hump_check: CamelCase-имена',
        'st_sniff': 'sniff: jpg/png/webp/ogg/mp4/webm/tgs',
        'st_sniff_deep': 'sniff deep: вложенный jpg',
        'st_sniff_svg': 'sniff: svg',
        'st_keykind': 'key_kind: document/thumb/chunk/web',
        'st_mn_voice': 'media_name: voice_19-циферный file_id',
        'st_mn_photo': 'media_name: photo с size-letter',
        'st_mn_video': 'media_name: video из chunk (doc_id = low>>32)',
        'st_binlog': 'parse_binlog: StoreWithTime -> store_time',
        'st_peerid': 'decode_peer_id: modern user/channel + legacy',
        'st_playback': 'parse_playback: doc_id + позиция',
        'st_hashtags': 'parse_hashtags_bots',
        'st_sugg': 'parse_search_suggestions: имя/телефон/username/rating',
        'st_john': 'john_hash: формат $telegram$2*100000*salt*key',
        'st_extractkey': 'extract_local_key на синтетике',
        'st_lang_tables': 'таблицы языков ru/en идентичны',
        'cli_tdata': 'путь к папке tdata (или к родителю с tdata)',
        'cli_out': 'папка вывода',
        'cli_passcode': 'локальный пароль (если установлен)',
        'cli_john': 'вывести хеш локального пароля для JtR/hashcat ($telegram$2) и выйти',
        'cli_lang': 'язык интерфейса, лога и отчёта: ru или en (запоминается)',
        'cli_nogui': 'запуск без GUI',
        'cli_selftest': 'самопроверки и выход',
        'cli_no_sort': 'не раскладывать медиа по папкам',
        'cli_no_merge': 'не склеивать видео-слайсы',
        'cli_no_clean': 'не чистить текстовый дамп',
        'cli_no_rawdump': 'не сохранять сырой дамп текстов',
        'cli_keep_staging': 'оставить папку .staging (сырые расшифрованные блобы)',
        'cli_no_tdata': '[X] tdata не найден',
        'cli_no_key': '[X] key_datas/key_datass не читается',
        'cli_john_hint': '# john --format=telegram hash.txt  (после брутфорса: --passcode <пароль>)',
        'cli_no_gui': '[X] GUI недоступен ({e}); укажите пути: python TDataDecrypter.py <tdata> <out>',
        'fld_tdata': 'Папка tdata:',
        'browse': 'Обзор…',
        'fld_out': 'Папка вывода:',
        'fld_pass': 'Локальный пароль:',
        'opt_sort': 'Раскладывать медиа по папкам',
        'opt_merge': 'Склеивать видео из слайсов',
        'opt_clean': 'Чистить тексты от мусора',
        'opt_raw': 'Сохранять сырой дамп текстов',
        'opt_staging': 'Оставить .staging',
        'btn_start': 'СТАРТ',
        'btn_cancel': 'Отмена',
        'btn_open': 'Открыть папку результата',
        'ready': 'Готов к запуску',
        'banner': 'расшифровка tdata.',
        'hint': 'Укажите папку tdata и папку вывода, затем нажмите СТАРТ.',
        'ttl_tdata': 'Выберите папку tdata',
        'ttl_out': 'Куда сохранять результат',
        'err_no_tdata': 'Нет tdata',
        'err_no_tdata_msg': 'Укажите существующую папку tdata (или родителя, внутри которого лежит tdata).',
        'err_no_out': 'Нет папки вывода',
        'err_no_out_msg': 'Укажите папку вывода.',
        'ask_overwrite': 'Папка не пустая',
        'ask_overwrite_msg': 'Папка вывода не пустая:\n{out}\n\nПродолжить? (файлы с совпадающими именами перезапишутся)',
        'log_start': 'Старт: tdata={tdata}',
        'internal_err': 'внутренняя ошибка: {e}',
        'cancelling': 'Отмена… (завершаю текущий шаг)',
        'open_fail': 'Не удалось открыть',
        'ask_exit': 'Идёт работа',
        'ask_exit_msg': 'Пайплайн ещё выполняется. Прервать и выйти?',
        'done_lbl': 'Готово — 100%',
        'log_done': 'ЗАВЕРШЕНО УСПЕШНО. Результат: {out}',
        'log_time': 'время: {t} c',
        'info_done': 'Готово',
        'info_done_msg': 'Готово!\nРезультат: {out}\n\nphotos/ · videos/ · stickers/ · voice/ · texts/ · report.txt',
        'stopped_lbl': 'Прервано / ошибка',
        'log_stopped': 'Прервано или ошибка — см. лог и report.txt',
        'ask_pass': 'Нужен пароль?',
        'ask_pass_msg': 'Не удалось расшифровать key_datas.\n\nВозможно, в AyuGram установлен локальный пароль.\nВвести его сейчас и повторить?',
        'ask_pass_ttl': 'Локальный пароль',
        'ask_pass_lbl': 'Локальный пароль tdata:',
        'lang_switched': 'язык интерфейса: {name}',
    },
    'en': {
        'pycryptodome_missing': '[!] pycryptodome required:  pip install pycryptodome',
        'key_missing': 'key file (key_datass / key_datas0 / key_datas1) not found',
        'key_not_tdf': '{name}: not a TDF file',
        'key_parse_fail': '{name}: failed to parse salt/keyEncrypted/infoEncrypted',
        'key_bad_salt': 'unexpected salt size: {n} (must be 32)',
        'key_info_ok': ', info verified (accounts: {n})',
        'key_ok': 'LocalKey extracted from {name} (mode: {kind}, tdata version: {version}{note})',
        'key_wrong_pass': 'failed to decrypt keyEncrypted — wrong local password?',
        'key_john_hint': ' (brute-force hash: --john)',
        'key_no_decrypt': 'failed to decrypt keyEncrypted (neither modern nor legacy){hint}',
        'map_not_tdf': '{name}: not a TDF',
        'map_bad_struct': '{name}: map structure not recognized',
        'map_not_decrypted': '{name}: map not decrypted',
        'map_truncated': '{name}: map truncated (partially read)',
        'act_account': '=== Account {name} ===',
        'act_top': '-- Frequently opened (top peers):',
        'act_recent': '-- Recent peers (search):',
        'act_sent_tags': '-- Sent hashtags: ',
        'act_search_tags': '-- Searched hashtags: ',
        'act_bots': '-- Recent bots: ',
        'act_playback': '-- Playback positions (the second viewing stopped at):',
        'log_activity': '[+] activity: activity/activity.txt + activity.json (peers: {p}, video positions: {v})',
        'src_self': 'PROFILE (selfSerialized: name/phone/username)',
        'src_settings': 'SETTINGS (settingss)',
        'src_usertag': 'USERTAG (usertag)',
        'src_account': 'ACCOUNT {base}',
        'src_other': 'SOURCE: {tag}',
        'texts_title': 'TEXTS EXTRACTED FROM TDATA',
        'texts_note': 'Sources: account map files (drafts, selfSerialized, sticker pack\nnames), settingss, usertag. Chat history is NOT stored in tdata — it\nlives on Telegram servers only. Junk is filtered automatically\n(CamelCase analysis + EN/RU bigrams).',
        'texts_group': '--- {title} ({n} lines) ---',
        'ayu_copy_fail': '[!] ayudata.db not copied: {e}',
        'ayu_dumped': '[+] AyuGram ayudata.db: deleted messages: {d}, edit histories: {e} (see ayugram/)',
        'ayu_read_fail': '[!] ayudata.db not read: {e}',
        'ayu_err': '[!] ayudata: {e}',
        'binlog_ok': '[+] binlog parsed: {rel} ({n} entries)',
        'binlog_fail': '[!] binlog not read: {e}',
        'checksum_fail': '[!] checksum mismatch: {place} (saving anyway)',
        'merged_holes': '[~] {name}: merged with gaps ({filled}/{total} bytes) — slices in cache are incomplete',
        'merge_fail': '[!] slice merge {high}... failed: {e}',
        'parse_skip': '[~] parsing {name} skipped: {e}',
        'no_headers': '[i] no video headers found in media_cache — nothing to merge',
        'headers_merged': '[i] duplicate headers merged: {n}',
        'recon_stats': '[i] videos with headers: {n}, candidate slices: {m}',
        'mode_verified': 'VERIFIED ({kb} KB matched)',
        'mode_assumed': 'ASSUMED (full 8MB slot)',
        'mode_assumed_tail': 'ASSUMED-TAIL (completeness {pct}%)',
        'slice_assign': '    {name}: slice {k} <- {file}: {mode}',
        'status_partial': 'PARTIAL {f}/{t} MB ({p}%)',
        'status_fragment': 'FRAGMENT {f}/{t} MB ({p}%, no moov)',
        'assembly_fail': '[!] assembly of {name} failed: {e}',
        'unassigned': '[i] unassigned slices: {n} (no owner found)',
        'stage_fmt': 'Stage {n}: {name}',
        'rep_stage_fmt': '\n=== Stage {n}: {name} ===',
        'st_search': 'Locating tdata',
        'st_key': 'Extracting LocalKey',
        'st_ayu': 'AyuGram ayudata.db',
        'st_settings': 'Settings, usertag, account map files, drafts',
        'st_cache': 'user_* cache databases',
        'st_sort': 'Media validation and sorting',
        'st_move': 'Moving caches as-is',
        'st_merge': 'Merging videos from media_cache slices',
        'st_classify': 'Classifying remaining media_cache files',
        'st_texts': 'Texts: cleaning the dump',
        'st_index': 'Media index and cleanup',
        'st_summary': 'Summary',
        'cancelled_by_user': 'CANCELLED by user',
        'critical_err': 'CRITICAL ERROR: {e}',
        'path_not_found': 'path not found: {path}',
        'tdata_not_found': 'folder with key_datass/key_datas* not found (is this really tdata?)',
        'tdata_found': 'tdata found: {path}',
        'accounts_found': 'accounts: {a}, cache databases (user_*): {c}',
        'prog_cache': 'cache: {d}/{t}',
        'prog_media': 'media: {d}/{t}',
        'processed_file': 'processed {fn}',
        'texts_dumped': 'texts into raw dump: {n}, embedded media from TDF: {m}',
        'cache_done': 'cache {rel}: blobs extracted: {n}',
        'no_cache': 'cache databases not found (or empty)',
        'staging_files': 'files in cache staging: {n} (duplicates dropped: {d})',
        'merge_videos_fail': '[!] video merge failed ({e}) — skipping, the rest is unaffected',
        'mc_classified': 'classified from media_cache additionally: {k}, embedded media extracted: {e}',
        'texts_cleaned': 'human-readable lines: {k}, junk filtered: {d}',
        'clean_fail': '[!] text cleaning failed: {e} (keeping raw dump)',
        'index_fail': '[!] media index not written: {e}',
        'activity_fail': '[!] activity not written: {e}',
        'activity_err': '[!] activity ({name}): {e}',
        'index_written': '[+] media_index.jsonl: {n} files with file_id/dc/time (mtime restored from cache time)',
        'texts_fail': '[!] texts from {src}: {e}',
        'deep_fail': '[!] deep media from {src}: {e}',
        'self_serialized': '[+] selfSerialized: {n} lines (name/phone/username)',
        'drafts_found': '[+] drafts found: {n}',
        'stats_photos': 'photos:          {n} (+{p} truncated)',
        'stats_videos': 'videos:          {n} (+partial see videos/partial)',
        'stats_tgs': 'tgs stickers:    {n}',
        'stats_webp': 'webp stickers:   {n}',
        'stats_webm': 'webm stickers:   {n}',
        'stats_voice': 'voice (ogg):     {n}',
        'stats_files': 'other files:     {n}',
        'stats_junk': 'junk discarded:   {n}',
        'stats_broken': 'broken jpg/png/webp/tgs/ogg: {n}',
        'stats_mp4_nomov': 'mp4 without moov (slices/fragments): {n}',
        'stats_mp4_trunc': 'mp4 truncated:   {n}',
        'stats_dupes': 'duplicates removed (SHA256): {n}',
        'stats_recon': 'video headers merged: {n} (slices used: {s})',
        'stats_embedded': 'embedded media from TDF: {n}',
        'stats_texts': 'texts total (raw): {n}',
        'rep_ok': 'SUCCESS',
        'rep_fail': 'CANCELLED/ERROR',
        'rep_title': '{app} — report',
        'rep_status': 'Status: {s}',
        'rep_out': 'Output: {p}',
        'rep_time': 'Time: {t} s',
        'rep_total': 'TOTAL:',
        'done_out': 'Done. Output: {out}',
        'st_all_ok': 'ALL TESTS PASSED',
        'st_failed': 'FAILED: {n}: {fails}',
        'st_xxh32_empty': 'xxh32("") == 0x2CC5D05',
        'st_xxh32_a': 'xxh32("a") == 0x550D7456',
        'st_ige_rt': 'IGE roundtrip',
        'st_ige_tgcrypto': 'IGE == tgcrypto',
        'st_decryptlocal_rt': 'DecryptLocal roundtrip',
        'st_decryptlocal_bad': 'DecryptLocal rejects corrupted data',
        'st_createkey_det': 'CreateLocalKey determinism',
        'st_trim_garbage': 'trim_jpeg cuts garbage after EOI',
        'st_trim_noeoi': 'trim_jpeg without EOI -> None',
        'st_jpeg_ok': 'jpeg_sane accepts structural JPEG',
        'st_jpeg_junk': 'jpeg_sane rejects false SOI from random bytes',
        'st_tgs_ok': 'val_tgs accepts Lottie and trims the tail',
        'st_tgs_bad': 'val_tgs rejects non-gzip',
        'st_mp4walk64': 'mp4_walk: 64-bit mdat + moov, structure intact',
        'st_valmp4_ok': 'val_mp4: ok + small tail trimming',
        'st_valmp4_trunc': 'val_mp4: truncation detected',
        'st_valmp4_nomov': 'val_mp4: no-moov (slice fragment)',
        'st_wbs': 'walk_boxes_store over chunks == mp4_walk',
        'st_verify': 'ChunkStore.verify checks bytes',
        'st_psv_complex': 'parse_slice_value: complex map',
        'st_psm_eq': 'parse_slice_map == parse_slice_value (complex)',
        'st_psm_plain': 'parse_slice_map: plain 256K slice',
        'st_isp_plain': 'is_slice_parts: plain 256K = yes',
        'st_isp_bad': 'is_slice_parts: complex with bad offsets = no',
        'st_keep_human': 'is_keep: human-like text kept',
        'st_keep_junk': 'is_keep: junk filtered out',
        'st_hump': 'hump_check: CamelCase names',
        'st_sniff': 'sniff: jpg/png/webp/ogg/mp4/webm/tgs',
        'st_sniff_deep': 'sniff deep: embedded jpg',
        'st_sniff_svg': 'sniff: svg',
        'st_keykind': 'key_kind: document/thumb/chunk/web',
        'st_mn_voice': 'media_name: voice_19-digit file_id',
        'st_mn_photo': 'media_name: photo with size-letter',
        'st_mn_video': 'media_name: video from chunk (doc_id = low>>32)',
        'st_binlog': 'parse_binlog: StoreWithTime -> store_time',
        'st_peerid': 'decode_peer_id: modern user/channel + legacy',
        'st_playback': 'parse_playback: doc_id + position',
        'st_hashtags': 'parse_hashtags_bots',
        'st_sugg': 'parse_search_suggestions: name/phone/username/rating',
        'st_john': 'john_hash: $telegram$2*100000*salt*key format',
        'st_extractkey': 'extract_local_key on synthetic data',
        'st_lang_tables': 'ru/en language tables identical',
        'cli_tdata': 'path to the tdata folder (or its parent)',
        'cli_out': 'output folder',
        'cli_passcode': 'local password (if set)',
        'cli_john': 'print the local-password hash for JtR/hashcat ($telegram$2) and exit',
        'cli_lang': 'interface, log and report language: ru or en (remembered)',
        'cli_nogui': 'run without GUI',
        'cli_selftest': 'self-tests and exit',
        'cli_no_sort': 'do not sort media into folders',
        'cli_no_merge': 'do not merge video slices',
        'cli_no_clean': 'do not clean the text dump',
        'cli_no_rawdump': 'do not keep the raw text dump',
        'cli_keep_staging': 'keep the .staging folder (raw decrypted blobs)',
        'cli_no_tdata': '[X] tdata not found',
        'cli_no_key': '[X] key_datas/key_datass not readable',
        'cli_john_hint': '# john --format=telegram hash.txt  (after brute-force: --passcode <password>)',
        'cli_no_gui': '[X] GUI unavailable ({e}); specify paths: python TDataDecrypter.py <tdata> <out>',
        'fld_tdata': 'tdata folder:',
        'browse': 'Browse…',
        'fld_out': 'Output folder:',
        'fld_pass': 'Local password:',
        'opt_sort': 'Sort media into folders',
        'opt_merge': 'Merge videos from slices',
        'opt_clean': 'Clean up texts',
        'opt_raw': 'Keep raw text dump',
        'opt_staging': 'Keep .staging',
        'btn_start': 'START',
        'btn_cancel': 'Cancel',
        'btn_open': 'Open result folder',
        'ready': 'Ready',
        'banner': 'tdata decryption.',
        'hint': 'Set the tdata folder and the output folder, then press START.',
        'ttl_tdata': 'Select the tdata folder',
        'ttl_out': 'Select the output folder',
        'err_no_tdata': 'No tdata',
        'err_no_tdata_msg': 'Set an existing tdata folder (or a parent folder containing tdata).',
        'err_no_out': 'No output folder',
        'err_no_out_msg': 'Set the output folder.',
        'ask_overwrite': 'Folder not empty',
        'ask_overwrite_msg': 'Output folder is not empty:\n{out}\n\nContinue? (files with matching names will be overwritten)',
        'log_start': 'Start: tdata={tdata}',
        'internal_err': 'internal error: {e}',
        'cancelling': 'Cancelling… (finishing current step)',
        'open_fail': 'Failed to open',
        'ask_exit': 'Running',
        'ask_exit_msg': 'The pipeline is still running. Abort and exit?',
        'done_lbl': 'Done — 100%',
        'log_done': 'FINISHED OK. Result: {out}',
        'log_time': 'time: {t} s',
        'info_done': 'Done',
        'info_done_msg': 'Done!\nResult: {out}\n\nphotos/ · videos/ · stickers/ · voice/ · texts/ · report.txt',
        'stopped_lbl': 'Cancelled / error',
        'log_stopped': 'Cancelled or failed — see the log and report.txt',
        'ask_pass': 'Password required?',
        'ask_pass_msg': 'Failed to decrypt key_datas.\n\nA local password may be set.\nEnter it now and retry?',
        'ask_pass_ttl': 'Local password',
        'ask_pass_lbl': 'tdata local password:',
        'lang_switched': 'interface language: {name}',
    },
}

_LANG = ['ru']


def cur_lang():
    return _LANG[0]


def set_lang(lang):
    if lang in STR:
        _LANG[0] = lang


def tr(key, **fmt):
    table = STR.get(_LANG[0]) or STR['ru']
    s = table.get(key)
    if s is None:
        s = STR['ru'].get(key, key)
    if fmt:
        try:
            s = s.format(**fmt)
        except (KeyError, IndexError):
            pass
    return s


def load_saved_lang():
    try:
        with open(CFG_PATH, encoding='utf-8') as f:
            v = json.load(f).get('lang')
        return v if v in STR else None
    except Exception:
        return None


def save_lang_cfg(lang):
    try:
        with open(CFG_PATH, 'w', encoding='utf-8') as f:
            json.dump({'lang': lang}, f)
    except Exception:
        pass


try:
    from Crypto.Cipher import AES
except ImportError:
    print(tr('pycryptodome_missing'))
    sys.exit(1)

try:
    import tgcrypto
except ImportError:
    tgcrypto = None

MASK32 = 0xFFFFFFFF
M32 = 0xFFFFFFFF

K_PART_SIZE = 128 * 1024
K_IN_SLICE = 8 * 1024 * 1024

GOOD_BOXES = {b'ftyp', b'moov', b'mdat', b'moof', b'sidx', b'free', b'skip',
              b'wide', b'uuid', b'styp', b'ssix', b'prft', b'emsg', b'mfra', b'pdin'}


class CancelledError(Exception):
    pass


def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if tgcrypto is not None:
        return tgcrypto.ige256_decrypt(data, key, iv)
    ecb = AES.new(key, AES.MODE_ECB)
    x, y = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        d = ecb.decrypt(bytes(a ^ b for a, b in zip(c, y)))
        p = bytes(a ^ b for a, b in zip(d, x))
        out += p
        x, y = c, p
    return bytes(out)


def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    h = hashlib.sha512(salt + passcode + salt).digest()
    iters = 1 if not passcode else 100_000
    return hashlib.pbkdf2_hmac('sha512', h, salt, iters, dklen=256)


def create_legacy_local_key(passcode: bytes, salt: bytes) -> bytes:
    iters = 4 if not passcode else 4000
    return hashlib.pbkdf2_hmac('sha1', passcode, salt, iters, dklen=256)


def prepare_aes_oldmtp(key256: bytes, msg_key: bytes, x: int = 8):
    sha_a = hashlib.sha1(msg_key + key256[x:x + 32]).digest()
    sha_b = hashlib.sha1(key256[32 + x:48 + x] + msg_key + key256[48 + x:64 + x]).digest()
    sha_c = hashlib.sha1(key256[64 + x:96 + x] + msg_key).digest()
    sha_d = hashlib.sha1(msg_key + key256[96 + x:128 + x]).digest()
    aes_key = sha_a[:8] + sha_b[8:20] + sha_c[4:16]
    aes_iv = sha_a[8:20] + sha_b[:8] + sha_c[16:20] + sha_d[:8]
    return aes_key, aes_iv


def decrypt_local(local_key: bytes, blob: bytes):
    if len(blob) <= 16 or (len(blob) & 0x0F):
        return None
    msg_key, enc = blob[:16], blob[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, x=8)
    try:
        dec = ige256_decrypt(enc, aes_key, aes_iv)
    except Exception:
        return None
    if hashlib.sha1(dec).digest()[:16] != msg_key:
        return None
    data_len = struct.unpack('<I', dec[:4])[0]
    if data_len < 4 or data_len > len(dec):
        return None
    return dec[4:data_len]


def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    ecb = AES.new(key, AES.MODE_ECB)
    x, y = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        p = data[i:i + 16]
        c = bytes(a ^ b for a, b in zip(
            ecb.encrypt(bytes(u ^ v for u, v in zip(p, x))), y))
        out += c
        x, y = c, p
    return bytes(out)


def encrypt_local(local_key: bytes, payload: bytes) -> bytes:
    full = struct.pack('<I', 4 + len(payload)) + payload
    if len(full) % 16:
        full += os.urandom(16 - len(full) % 16)
    msg_key = hashlib.sha1(full).digest()[:16]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, x=8)
    return msg_key + ige256_encrypt(full, aes_key, aes_iv)


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


def open_tdef(path: str, local_key: bytes):
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    if len(raw) < 4 + 64 + 48 + 16 or raw[:4] != b'TDEF':
        return None
    salt = raw[4:68]
    key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:64]).digest()[:16]
    body = raw[68:]
    usable = len(body) - (len(body) % 16)
    if usable < 48:
        return None
    ctr = AES.new(key, AES.MODE_CTR, nonce=b'',
                  initial_value=int.from_bytes(iv, 'big'))
    dec = ctr.decrypt(body[:usable])
    if hashlib.sha256(local_key + salt + dec[:16]).digest() != dec[16:48]:
        return None
    return dec[48:]


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


TAG_PREFIX = {1: 'image', 2: 'sticker', 3: 'voice', 4: 'round', 5: 'gif'}
TAG_NAMES = {0: 'generic', 1: 'image', 2: 'sticker', 3: 'voice_message',
             4: 'video_message', 5: 'animation'}
KEY_KINDS = ((0xFFFFFFFFFFFFFF00, 0x0000000000000100, 'document'),
             (0xFFFFFFFFFFFFFF00, 0x0000000000000200, 'document_thumb'),
             (0xFFFFFFFFFFFFFF00, 0x0000000000000300, 'album_thumb'),
             (0x0000FF0000000000, 0x0000010000000000, 'document_chunk'),
             (0x000000FF00000000, 0x0000000100000000, 'photo_chunk'),
             (0xFFFFFF0000000000, 0x0000020000000000, 'web_document'),
             (0xFFFFFF0000000000, 0x0000030000000000, 'url'),
             (0xFFFFFF0000000000, 0x0000040000000000, 'geo_point'))


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


LSK_SUBFILES = {0x09: 'user_settings', 0x0A: 'hashtags_bots', 0x0F: 'saved_gifs',
                 0x11: 'trusted_peers', 0x12: 'faved_stickers', 0x13: 'export_settings',
                 0x18: 'search_suggestions', 0x1C: 'media_playback', 0x1E: 'prefs'}


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


PEER_VERSION_TAG = 0x77FFFFFFFFFFFFFF
MODERN_IMAGE_TAG = -(2 ** 31)


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


def write_activity(out_dir: str, activity: dict, ui):
    if not activity:
        return
    act_dir = os.path.join(out_dir, 'activity')
    os.makedirs(act_dir, exist_ok=True)
    lines = []
    for acct_name, data in activity.items():
        lines.append(tr('act_account', name=acct_name))
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
    for tag in sorted(groups, key=lambda t: -len(groups[t])):
        out.append(tr('texts_group', title=source_title(tag), n=len(groups[tag])))
        for text in groups[tag]:
            out.append(text)
        out.append('')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))
    return kept, dropped


def sniff_media(data: bytes, deep: bool = False):
    def at(off):
        if data[off:off + 3] == b'\xff\xd8\xff':
            return ('jpg', off)
        if data[off:off + 8] == b'\x89PNG\r\n\x1a\n':
            return ('png', off)
        if data[off:off + 6] in (b'GIF87a', b'GIF89a'):
            return ('gif', off)
        if data[off:off + 4] == b'OggS':
            return ('ogg', off)
        if data[off:off + 4] == b'\x1aE\xdf\xa3':
            return ('webm', off)
        if data[off:off + 3] == b'ID3' or (len(data) > off + 2 and data[off] == 0xFF and data[off + 1] in (0xFB, 0xF3, 0xF2)):
            return ('mp3', off)
        if data[off:off + 4] == b'%PDF':
            return ('pdf', off)
        if data[off:off + 4] == b'RIFF' and data[off + 8:off + 12] == b'WEBP':
            return ('webp', off)
        if data[off:off + 4] == b'RIFF' and data[off + 8:off + 12] == b'WAVE':
            return ('wav', off)
        if data[off + 4:off + 8] == b'ftyp':
            brand = data[off + 8:off + 12]
            if brand in (b'avif', b'avis'):
                return ('avif', off)
            if brand == b'qt  ':
                return ('mov', off)
            return ('mp4', off)
        if data[off:off + 3] == b'\x1f\x8b\x08':
            return ('tgs', off)
        if data[off:off + 16] == b'SQLite format 3\x00':
            return ('sqlite', off)
        if data[off:off + 4] == b'<svg' or (
                data[off:off + 5] == b'<?xml' and b'<svg' in data[off:off + 512]):
            return ('svg', off)
        return (None, off)

    ext, off = at(0)
    if ext:
        return ext, 0
    if deep:
        try:
            for sig in (b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'OggS',
                        b'GIF87a', b'GIF89a', b'%PDF'):
                pos = data.find(sig)
                if pos > 0:
                    ext2, off2 = at(pos)
                    if ext2:
                        return ext2, pos
        except Exception:
            return None, 0
    return None, 0


def trim_jpeg(d):
    if d[:3] != b'\xff\xd8\xff':
        return None
    i = d.rfind(b'\xff\xd9')
    if i >= 0:
        return d[:i + 2]
    return None


def jpeg_sane(d, limit_segments=48) -> bool:
    if len(d) < 8 or d[:3] != b'\xff\xd8\xff':
        return False
    i, saw_sof, saw_dqt, saw_sos = 2, False, False, False
    for _ in range(limit_segments):
        if i + 2 > len(d):
            break
        if d[i] != 0xFF:
            return False
        m = d[i + 1]
        if m in (0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xD9:
            break
        if m == 0xDA:
            saw_sos = True
            break
        if i + 4 > len(d):
            return False
        ln = struct.unpack('>H', d[i + 2:i + 4])[0]
        if ln < 2 or i + 2 + ln > len(d):
            return False
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            saw_sof = True
        if m == 0xDB:
            saw_dqt = True
        i += 2 + ln
    return saw_sof and (saw_sos or saw_dqt)


def first_gzip_member(d):
    if d[:3] != b'\x1f\x8b\x08':
        return None
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        dec.decompress(d)
        dec.flush()
        end = len(d) - len(dec.unused_data)
        return d[:end] if end else None
    except Exception:
        return None


def val_tgs(d):
    t = first_gzip_member(d)
    if not t:
        return None
    try:
        j = json.loads(gzip.decompress(t))
        if isinstance(j, dict) and ('layers' in j or 'body' in j
                                    or ('fr' in j and 'op' in j)):
            return t
    except Exception:
        pass
    return None


def val_webp(d):
    return d[:4] == b'RIFF' and d[8:12] == b'WEBP' and d[12:16] in (b'VP8 ', b'VP8L', b'VP8X')


def val_webm(d):
    return d[:4] == b'\x1aE\xdf\xa3'


def val_ogg(d):
    if d[:4] != b'OggS':
        return False
    return b'OpusHead' in d[:512] or d.count(b'OggS') >= 2


def mp4_walk(d):
    pos = 0
    n = len(d)
    boxes = []
    while pos + 8 <= n:
        size = struct.unpack('>I', d[pos:pos + 4])[0]
        typ = d[pos + 4:pos + 8]
        if size == 1:
            if pos + 16 > n:
                return boxes, pos, False
            size = struct.unpack('>Q', d[pos + 8:pos + 16])[0]
            if size < 16:
                return boxes, pos, False
        elif size < 8:
            return boxes, pos, False
        if typ not in GOOD_BOXES:
            return boxes, pos, False
        boxes.append((pos, size, typ))
        if pos + size > n:
            return boxes, pos + size, False
        pos += size
    return boxes, pos, pos == n


def val_mp4(d):
    boxes, end, ok = mp4_walk(d)
    if not boxes or b'moov' not in [t for _, _, t in boxes]:
        return False, 'no-moov', d
    if end > len(d):
        return False, 'truncated', d
    if len(d) - end > 16:
        return False, 'garbage-tail', d
    return True, 'ok', d[:end]


def dump_ayudata(tdata: str, out_dir: str, ui):
    src = os.path.join(tdata, 'ayudata.db')
    if not os.path.isfile(src):
        return False
    ayu_dir = os.path.join(out_dir, 'ayugram')
    os.makedirs(ayu_dir, exist_ok=True)
    try:
        shutil.copy2(src, os.path.join(ayu_dir, 'ayudata.db'))
    except OSError as e:
        ui.log(tr('ayu_copy_fail', e=e), 'warn')
        return False
    try:
        con = sqlite3.connect(f'file:{src}?mode=ro&immutable=1', uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        rows_deleted = rows_edited = 0
        if 'DeletedMessage' in tables:
            with open(os.path.join(ayu_dir, 'deleted_messages.txt'), 'w', encoding='utf-8') as f:
                cur.execute("SELECT dialogId, fromId, messageId, date, text, mediaPath "
                            "FROM DeletedMessage ORDER BY date")
                for dlg, frm, mid, date, text, media in cur.fetchall():
                    rows_deleted += 1
                    f.write(f"dialog={dlg} from={frm} msg={mid} date={date}\n"
                            f"  text: {text!r}\n  media: {media}\n")
        if 'EditedMessage' in tables:
            with open(os.path.join(ayu_dir, 'edited_messages.txt'), 'w', encoding='utf-8') as f:
                cur.execute("SELECT dialogId, fromId, messageId, date, editDate, text "
                            "FROM EditedMessage ORDER BY messageId, editDate")
                for dlg, frm, mid, date, edate, text in cur.fetchall():
                    rows_edited += 1
                    f.write(f"dialog={dlg} from={frm} msg={mid} date={date} edited={edate}\n"
                            f"  text: {text!r}\n")
        con.close()
        ui.log(tr('ayu_dumped', d=rows_deleted, e=rows_edited), 'ok')
        return True
    except sqlite3.Error as e:
        ui.log(tr('ayu_read_fail', e=e), 'warn')
        return True


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
            try:
                items.sort(key=lambda x: x[0])
                base = items[0][0]
                base_e = items[0][2]
                by_low = {low: (data, e) for low, data, e in items}
                parts0, rem0, complex0 = parse_slice_value(items[0][1])
                header_case = bool(complex0 and (base + 1) not in by_low
                                   and (base + 2) in by_low)
                chunks = {}
                for low, data, _e in items:
                    delta = low - base
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
                    continue
                total = max(o + len(b) for o, b in chunks.items())
                buf = bytearray(total)
                filled = 0
                for off, b in chunks.items():
                    buf[off:off + len(b)] = b
                    filled += len(b)
                ext, _ = sniff_media(bytes(buf[:64]))
                stem = media_name(high, base, base_e[2])
                name = stem + (f'.{ext}' if ext else '')
                with open(os.path.join(target, name), 'wb') as f:
                    f.write(buf)
                saved += 1
                index_entries.append({'stem': stem, 'kind': key_kind(high),
                                      'file_id': str(media_id_of(high, base)),
                                      'dc': high & 0xFF,
                                      'tag': TAG_NAMES.get(base_e[2], base_e[2]),
                                      'size': total, 'stored': base_e[6], 'used': base_e[7],
                                      'high': f'{high:016x}', 'low': f'{base:016x}',
                                      'merged': True})
                if filled < total:
                    ui.log(tr('merged_holes', name=name, filled=filled,
                              total=total), 'warn')
            except Exception as e:
                ui.log(tr('merge_fail', high=f'{high:016x}', e=e), 'warn')
    return saved, index_entries


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
        v['T'] = max(end_by_boxes or 0, span)
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


PARTIAL_MIN_JPEG = 8000
MIN_JPEG = 600


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


class Options:
    def __init__(self):
        self.sort_media = True
        self.merge_videos = True
        self.clean_texts = True
        self.raw_dump = True
        self.keep_staging = False


class ConsoleUI:

    def __init__(self):
        self.cancelled = False

    def log(self, msg, level='info'):
        prefix = {'ok': '[+]', 'warn': '[!]', 'err': '[X]'}.get(level, '[i]')
        print(f'{prefix} {msg}', flush=True)

    def progress(self, frac, note=''):
        pass

    def stage(self, name):
        print(f'\n=== {name} ===', flush=True)


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
        if subkeys:
            try:
                act = extract_activity(acct, subkeys, self.local_key)
                if act:
                    self.activity[os.path.basename(acct)] = act
            except Exception as e:
                self.log(tr('activity_err', name=os.path.basename(acct), e=e),
                         'warn')
        if self_data:
            try:
                texts = extract_texts(self_data)
            except Exception:
                texts = []
            with open(self.msg_path, 'a', encoding='utf-8') as f:
                for t in texts:
                    f.write(f'[self] {t}\n')
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
                write_activity(out, self.activity, self.ui)
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

    def _fmt_keys(s):
        return sorted(re.findall(r'\{(\w+)\}', s))
    check('st_lang_tables', set(STR['ru']) == set(STR['en']) and all(
        _fmt_keys(STR['ru'][k]) == _fmt_keys(STR['en'][k]) for k in STR['ru']))

    print(f"\n{tr('st_all_ok') if not fails else tr('st_failed', n=len(fails), fails=fails)}")
    return not fails


def cli_main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pre_lang = None
    for i, a in enumerate(argv):
        if a == '--lang' and i + 1 < len(argv) and argv[i + 1] in ('ru', 'en'):
            pre_lang = argv[i + 1]
            break
        if a.startswith('--lang=') and a[7:] in ('ru', 'en'):
            pre_lang = a[7:]
            break
    if pre_lang:
        set_lang(pre_lang)
    elif os.environ.get('TDATADECRYPTER_LANG') in ('ru', 'en'):
        set_lang(os.environ['TDATADECRYPTER_LANG'])
    else:
        saved = load_saved_lang()
        if saved:
            set_lang(saved)

    ap = argparse.ArgumentParser(prog='TDataDecrypter')
    ap.add_argument('tdata', nargs='?', help=tr('cli_tdata'))
    ap.add_argument('out', nargs='?', help=tr('cli_out'))
    ap.add_argument('--passcode', default='', help=tr('cli_passcode'))
    ap.add_argument('--lang', choices=['ru', 'en'], help=tr('cli_lang'))
    ap.add_argument('--john', action='store_true',
                    help=tr('cli_john'))
    ap.add_argument('--nogui', action='store_true', help=tr('cli_nogui'))
    ap.add_argument('--selftest', action='store_true', help=tr('cli_selftest'))
    ap.add_argument('--no-sort', action='store_true', help=tr('cli_no_sort'))
    ap.add_argument('--no-merge', action='store_true', help=tr('cli_no_merge'))
    ap.add_argument('--no-clean', action='store_true', help=tr('cli_no_clean'))
    ap.add_argument('--no-rawdump', action='store_true', help=tr('cli_no_rawdump'))
    ap.add_argument('--keep-staging', action='store_true',
                    help=tr('cli_keep_staging'))
    args = ap.parse_args(argv)

    if args.lang and args.lang != pre_lang:
        set_lang(args.lang)
    if args.lang:
        save_lang_cfg(args.lang)

    if args.selftest:
        sys.exit(0 if selftest() else 3)

    if args.john:
        td = locate_tdata(args.tdata or '.')
        if not td:
            print(tr('cli_no_tdata'))
            sys.exit(1)
        jh = john_hash(td)
        if not jh:
            print(tr('cli_no_key'))
            sys.exit(1)
        print(jh)
        print(tr('cli_john_hint'), file=sys.stderr)
        sys.exit(0)

    if not args.tdata or not args.out:
        try:
            return run_gui()
        except Exception as e:
            print(tr('cli_no_gui', e=e))
            sys.exit(1)

    opts = Options()
    opts.sort_media = not args.no_sort
    opts.merge_videos = not args.no_merge
    opts.clean_texts = not args.no_clean
    opts.raw_dump = not args.no_rawdump
    opts.keep_staging = args.keep_staging

    print(f'{APP_TITLE} (CLI)')
    app = TDataDecrypter(args.tdata, args.out, args.passcode, opts, ConsoleUI())
    ok = app.run()
    sys.exit(0 if ok else 2)


def run_gui(demo=False):
    import tkinter as tk
    import tkinter.font as tkfont
    import queue
    import subprocess
    from tkinter import ttk, filedialog, messagebox

    BG = '#171922'
    PANEL = '#1f2230'
    PANEL2 = '#2a2e40'
    FG = '#e8eaf2'
    DIM = '#8b91a7'
    ACCENT = '#4f8cff'
    OK = '#4fd08a'
    WARN = '#f5b04c'
    ERR = '#f56a6a'
    ENTRY_BG = '#12141c'
    LOG_BG = '#101219'

    def pick_lang(parent=None):
        own = parent is None
        w = tk.Tk() if own else tk.Toplevel(parent)
        w.title(APP_TITLE)
        w.configure(bg=BG)
        w.resizable(False, False)
        w.geometry('320x150')
        choice = {}

        def go(lang):
            choice['lang'] = lang
            w.destroy()

        tk.Label(w, text='Выберите язык / Select language', bg=BG, fg=FG,
                 font=('Segoe UI', 11, 'bold')).pack(pady=(26, 16))
        brow = tk.Frame(w, bg=BG)
        brow.pack()
        for lang, name in (('ru', 'Русский'), ('en', 'English')):
            tk.Button(brow, text=name, command=lambda l=lang: go(l),
                      bg=PANEL2, fg=FG, activebackground=ACCENT,
                      activeforeground='#ffffff', relief='flat',
                      font=('Segoe UI', 10, 'bold'), width=12, pady=6,
                      cursor='hand2').pack(side='left', padx=8)
        w.protocol('WM_DELETE_WINDOW', lambda: go('ru'))
        if own:
            w.mainloop()
        else:
            w.transient(parent)
            w.grab_set()
            parent.wait_window(w)
        return choice.get('lang') or 'ru'

    env_lang = os.environ.get('TDATADECRYPTER_LANG')
    if env_lang in ('ru', 'en'):
        lang = env_lang
    else:
        lang = load_saved_lang()
        if not lang:
            lang = pick_lang()
            save_lang_cfg(lang)
    set_lang(lang)

    class GuiUI:

        def __init__(self):
            self.q = queue.Queue()
            self.cancelled = False

        def log(self, msg, level='info'):
            self.q.put(('log', level, msg))

        def progress(self, frac, note=''):
            self.q.put(('prog', frac, note))

        def stage(self, name):
            self.q.put(('stage', name))

    class App:
        def __init__(self, root):
            self.root = root
            self.gui_ui = GuiUI()
            self.worker = None
            self.last_out = None
            self.run_started_at = None
            self._build()
            self.root.after(60, self._poll)


        def _build(self):
            r = self.root
            r.title(APP_TITLE)
            r.configure(bg=BG)
            r.geometry('960x700')
            r.minsize(880, 640)

            style = ttk.Style(r)
            style.theme_use('clam')
            style.configure('.', background=PANEL, foreground=FG, borderwidth=0)
            style.configure('TFrame', background=PANEL)
            style.configure('Card.TFrame', background=PANEL, relief='flat')
            style.configure('TLabel', background=PANEL, foreground=FG)
            style.configure('Dim.TLabel', background=PANEL, foreground=DIM)
            style.configure('TButton', background=PANEL2, foreground=FG,
                            borderwidth=0, focusthickness=1, padding=(14, 8))
            style.map('TButton', background=[('active', '#343952')])
            style.configure('Accent.TButton', background=ACCENT, foreground='#ffffff',
                            padding=(26, 10), font=('Segoe UI', 10, 'bold'))
            style.map('Accent.TButton',
                      background=[('disabled', '#33507e'), ('active', '#6b9dff')])
            style.configure('Danger.TButton', background='#8c3a3a', foreground='#ffffff',
                            padding=(18, 8))
            style.map('Danger.TButton',
                      background=[('disabled', '#4a2c2c'), ('active', '#a84848')])
            style.configure('TCheckbutton', background=PANEL, foreground=FG,
                            focuscolor=PANEL, padding=(2, 2))
            style.map('TCheckbutton', background=[('active', PANEL)],
                      foreground=[('disabled', DIM)])
            style.configure('TEntry', fieldbackground=ENTRY_BG, foreground=FG,
                            insertcolor=FG, bordercolor=PANEL2, lightcolor=PANEL2,
                            darkcolor=PANEL2, padding=(8, 6))
            style.configure('Horizontal.TProgressbar', troughcolor=ENTRY_BG,
                            background=ACCENT, bordercolor=BG, lightcolor=ACCENT,
                            darkcolor=ACCENT, thickness=10)
            style.configure('Vertical.TScrollbar', troughcolor=LOG_BG,
                            background=PANEL2, bordercolor=LOG_BG,
                            arrowcolor=DIM, relief='flat')

            mono = 'Consolas' if 'Consolas' in tkfont.families() else 'Courier New'

            head = tk.Frame(r, bg=BG)
            head.pack(fill='x', padx=22, pady=(16, 8))
            tk.Label(head, text='TDataDecrypter', bg=BG, fg=FG,
                     font=('Segoe UI', 17, 'bold')).pack(side='left')
            self.lang_btn = tk.Button(head, text=cur_lang().upper(),
                                      command=self._switch_lang, bg=BG, fg=DIM,
                                      activebackground=BG, activeforeground=FG,
                                      relief='flat', font=('Segoe UI', 9, 'bold'),
                                      cursor='hand2')
            self.lang_btn.pack(side='right')

            card = tk.Frame(r, bg=PANEL, highlightthickness=1,
                            highlightbackground='#2c3044')
            card.pack(fill='x', padx=22, pady=6)

            self.var_tdata = tk.StringVar()
            self.var_out = tk.StringVar()
            self.var_pass = tk.StringVar()
            self.opt_sort = tk.BooleanVar(value=True)
            self.opt_merge = tk.BooleanVar(value=True)
            self.opt_clean = tk.BooleanVar(value=True)
            self.opt_raw = tk.BooleanVar(value=True)
            self.opt_staging = tk.BooleanVar(value=False)

            pad = dict(padx=14, pady=7)
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', **pad)
            self.lbl_tdata = tk.Label(row, text=tr('fld_tdata'), bg=PANEL, fg=FG,
                                      width=13, anchor='w')
            self.lbl_tdata.pack(side='left')
            ttk.Entry(row, textvariable=self.var_tdata).pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            self.btn_browse_t = ttk.Button(row, text=tr('browse'),
                                           command=self._pick_tdata, width=9)
            self.btn_browse_t.pack(side='left')

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=14, pady=(0, 7))
            self.lbl_out = tk.Label(row, text=tr('fld_out'), bg=PANEL, fg=FG,
                                    width=13, anchor='w')
            self.lbl_out.pack(side='left')
            ttk.Entry(row, textvariable=self.var_out).pack(
                side='left', fill='x', expand=True, padx=(4, 8))
            self.btn_browse_o = ttk.Button(row, text=tr('browse'),
                                           command=self._pick_out, width=9)
            self.btn_browse_o.pack(side='left')

            row = tk.Frame(card, bg=PANEL)
            row.pack(fill='x', padx=14, pady=(0, 10))
            self.lbl_pass = tk.Label(row, text=tr('fld_pass'), bg=PANEL, fg=DIM,
                                     width=13, anchor='w')
            self.lbl_pass.pack(side='left')
            ttk.Entry(row, textvariable=self.var_pass, show='•').pack(
                side='left', fill='x', expand=True, padx=(4, 8))

            card2 = tk.Frame(r, bg=PANEL, highlightthickness=1,
                             highlightbackground='#2c3044')
            card2.pack(fill='x', padx=22, pady=6)
            opts = [
                ('opt_sort', self.opt_sort),
                ('opt_merge', self.opt_merge),
                ('opt_clean', self.opt_clean),
                ('opt_raw', self.opt_raw),
                ('opt_staging', self.opt_staging),
            ]
            orow = tk.Frame(card2, bg=PANEL)
            orow.pack(fill='x', padx=14, pady=(10, 0))
            orow2 = tk.Frame(card2, bg=PANEL)
            orow2.pack(fill='x', padx=14, pady=(6, 10))
            self.checks = []
            for i, (key, var) in enumerate(opts):
                parent = orow if i < 3 else orow2
                cb = ttk.Checkbutton(parent, text=tr(key), variable=var)
                cb.pack(side='left', padx=(0, 16))
                self.checks.append((cb, key))

            act = tk.Frame(r, bg=BG)
            act.pack(fill='x', padx=22, pady=(10, 4))
            self.btn_start = ttk.Button(act, text=tr('btn_start'), style='Accent.TButton',
                                        command=self._start)
            self.btn_start.pack(side='left')
            self.btn_cancel = ttk.Button(act, text=tr('btn_cancel'), style='Danger.TButton',
                                         command=self._cancel, state='disabled')
            self.btn_cancel.pack(side='left', padx=10)
            self.btn_open = ttk.Button(act, text=tr('btn_open'),
                                       command=self._open_out, state='disabled')
            self.btn_open.pack(side='left')
            self.stage_lbl = tk.Label(act, text=tr('ready'), bg=BG, fg=DIM,
                                      font=('Segoe UI', 10))
            self.stage_lbl.pack(side='right')

            self.pbar = ttk.Progressbar(r, mode='determinate', maximum=1.0, value=0)
            self.pbar.pack(fill='x', padx=22, pady=(2, 8))

            logf = tk.Frame(r, bg=LOG_BG, highlightthickness=1,
                            highlightbackground='#2c3044')
            logf.pack(fill='both', expand=True, padx=22, pady=(0, 6))
            self.log_txt = tk.Text(logf, bg=LOG_BG, fg=FG, wrap='word',
                                   font=(mono, 9), relief='flat',
                                   state='disabled', padx=12, pady=10,
                                   insertbackground=FG)
            sb = ttk.Scrollbar(logf, command=self.log_txt.yview)
            self.log_txt.configure(yscrollcommand=sb.set)
            sb.pack(side='right', fill='y')
            self.log_txt.pack(side='left', fill='both', expand=True)
            for tag, color, bold in (('ok', OK, False), ('warn', WARN, False),
                                     ('err', ERR, True), ('info', FG, False),
                                     ('dim', DIM, False), ('stage', ACCENT, True)):
                self.log_txt.tag_configure(tag, foreground=color,
                                           font=(mono, 9, 'bold') if bold else (mono, 9))

            r.protocol('WM_DELETE_WINDOW', self._on_close)
            self._log(f"{APP_TITLE}: {tr('banner')}", 'stage')
            self._log(tr('hint'), 'dim')

        def _apply_lang(self):
            self.lbl_tdata.configure(text=tr('fld_tdata'))
            self.lbl_out.configure(text=tr('fld_out'))
            self.lbl_pass.configure(text=tr('fld_pass'))
            self.btn_browse_t.configure(text=tr('browse'))
            self.btn_browse_o.configure(text=tr('browse'))
            for cb, key in self.checks:
                cb.configure(text=tr(key))
            self.btn_start.configure(text=tr('btn_start'))
            self.btn_cancel.configure(text=tr('btn_cancel'))
            self.btn_open.configure(text=tr('btn_open'))
            self.lang_btn.configure(text=cur_lang().upper())
            if not (self.worker and self.worker.is_alive()):
                self.stage_lbl.configure(text=tr('ready'))

        def _switch_lang(self):
            if self.worker and self.worker.is_alive():
                return
            new = pick_lang(self.root)
            if new and new != cur_lang():
                set_lang(new)
                save_lang_cfg(new)
                self._apply_lang()
                self._log(tr('lang_switched',
                             name={'ru': 'Русский', 'en': 'English'}[new]), 'dim')


        def _pick_tdata(self):
            p = filedialog.askdirectory(title=tr('ttl_tdata'))
            if p:
                self.var_tdata.set(p)
                if not self.var_out.get():
                    self.var_out.set(os.path.join(os.path.dirname(p) or p,
                                                  'tdata_recovered'))

        def _pick_out(self):
            p = filedialog.askdirectory(title=tr('ttl_out'))
            if p:
                self.var_out.set(p)

        def _start(self):
            tdata = self.var_tdata.get().strip()
            out = self.var_out.get().strip()
            if not tdata or not os.path.isdir(tdata):
                messagebox.showerror(tr('err_no_tdata'), tr('err_no_tdata_msg'))
                return
            if not out:
                messagebox.showerror(tr('err_no_out'), tr('err_no_out_msg'))
                return
            if os.path.isdir(out) and os.listdir(out):
                if not messagebox.askyesno(
                        tr('ask_overwrite'),
                        tr('ask_overwrite_msg').format(out=out)):
                    return
            opts = Options()
            opts.sort_media = self.opt_sort.get()
            opts.merge_videos = self.opt_merge.get()
            opts.clean_texts = self.opt_clean.get()
            opts.raw_dump = self.opt_raw.get()
            opts.keep_staging = self.opt_staging.get()

            self.log_txt.configure(state='normal')
            self.log_txt.delete('1.0', 'end')
            self.log_txt.configure(state='disabled')
            self.btn_start.configure(state='disabled')
            self.btn_cancel.configure(state='normal')
            self.btn_open.configure(state='disabled')
            self.lang_btn.configure(state='disabled')
            self.pbar.configure(value=0)
            self.run_started_at = time.time()
            self.last_out = out
            self._log(tr('log_start').format(tdata=tdata), 'stage')

            def worker():
                try:
                    app = TDataDecrypter(tdata, out, self.var_pass.get(), opts,
                                         self.gui_ui)
                    ok = app.run()
                    self.gui_ui.q.put(('done', ok))
                except Exception as e:
                    self.gui_ui.q.put(('log', 'err', tr('internal_err').format(e=e)))
                    self.gui_ui.q.put(('done', False))

            self.worker = threading.Thread(target=worker, daemon=True)
            self.worker.start()

        def _cancel(self):
            if self.worker and self.worker.is_alive():
                self.gui_ui.cancelled = True
                self.stage_lbl.configure(text=tr('cancelling'))
                self.btn_cancel.configure(state='disabled')

        def _open_out(self):
            path = self.last_out
            if path and os.path.isdir(path):
                try:
                    if sys.platform.startswith('win'):
                        os.startfile(path)
                    elif sys.platform == 'darwin':
                        subprocess.Popen(['open', path])
                    else:
                        subprocess.Popen(['xdg-open', path])
                except Exception as e:
                    messagebox.showerror(tr('open_fail'), str(e))

        def _on_close(self):
            if self.worker and self.worker.is_alive():
                if not messagebox.askyesno(tr('ask_exit'), tr('ask_exit_msg')):
                    return
                self.gui_ui.cancelled = True
                self.root.after(300, self.root.destroy)
            else:
                self.root.destroy()


        def _poll(self):
            try:
                while True:
                    item = self.gui_ui.q.get_nowait()
                    kind = item[0]
                    if kind == 'log':
                        self._log(item[2], item[1])
                    elif kind == 'prog':
                        frac, note = item[1], item[2]
                        self.pbar.configure(value=max(0.0, min(1.0, frac)))
                        pct = int(frac * 100)
                        if note:
                            self.stage_lbl.configure(text=f'{pct}%  ·  {note}')
                        else:
                            self.stage_lbl.configure(text=f'{pct}%')
                    elif kind == 'stage':
                        self._log(f'— {item[1]} —', 'stage')
                        self.stage_lbl.configure(text=item[1])
                    elif kind == 'done':
                        self._on_done(item[1])
            except queue.Empty:
                pass
            self.root.after(60, self._poll)

        def _on_done(self, ok):
            self.btn_start.configure(state='normal')
            self.btn_cancel.configure(state='disabled')
            self.lang_btn.configure(state='normal')
            if ok:
                self.pbar.configure(value=1.0)
                self.stage_lbl.configure(text=tr('done_lbl'))
                self._log(tr('log_done').format(out=self.last_out), 'ok')
                if self.run_started_at:
                    self._log(tr('log_time').format(
                        t=f'{time.time() - self.run_started_at:.1f}'), 'dim')
                self.btn_open.configure(state='normal')
                try:
                    rep = os.path.join(self.last_out, 'report.txt')
                    if os.path.isfile(rep):
                        with open(rep, encoding='utf-8') as f:
                            tail = f.read().split(tr('rep_total'))[-1].strip()
                        if tail:
                            self._log('')
                            self._log(tr('rep_total'), 'stage')
                            for line in tail.splitlines():
                                if line.strip():
                                    self._log('  ' + line.strip(), 'ok')
                except Exception:
                    pass
                messagebox.showinfo(
                    tr('info_done'), tr('info_done_msg').format(out=self.last_out))
            else:
                self.stage_lbl.configure(text=tr('stopped_lbl'))
                self._log(tr('log_stopped'), 'warn')
                if not self.var_pass.get():
                    if messagebox.askyesno(tr('ask_pass'), tr('ask_pass_msg')):
                        self.var_pass.set(messagebox.askstring(
                            tr('ask_pass_ttl'), tr('ask_pass_lbl'), show='•') or '')
                        self._start()

        def _log(self, msg, level='info'):
            tag = level if level in ('ok', 'warn', 'err', 'dim', 'stage') else 'info'
            self.log_txt.configure(state='normal')
            self.log_txt.insert('end', msg + '\n', tag)
            self.log_txt.see('end')
            self.log_txt.configure(state='disabled')

    root = tk.Tk()
    app = App(root)

    if demo:
        app.var_tdata.set(r'C:\Users\user\AppData\Roaming\AyuGram\tdata')
        app.var_out.set(r'D:\recovered\tdata_recovered')
        app.pbar.configure(value=0.47)
        app.stage_lbl.configure(
            text=f"47%  ·  {tr('prog_cache', d=3408, t=7095)}")
        for line, lv in [
            ('[i] ' + tr('tdata_found', path='…\\AyuGram\\tdata'), 'info'),
            (tr('key_ok', name='key_datas', kind='modern', version='5',
                note=tr('key_info_ok', n=2)), 'ok'),
            (tr('self_serialized', n=3), 'ok'),
            (tr('cache_done', rel='user_data/cache', n=5660), 'info'),
            (tr('merged_holes', name='A1B2C3D4E5F6.mp4', filled=25311568,
                total=37951616), 'warn'),
        ]:
            app._log(line, lv)

        def _shot_and_close():
            shot = os.environ.get('TDATADECRYPTER_SHOT')
            if shot:
                try:
                    root.update_idletasks()
                    root.update()
                    from PIL import ImageGrab
                    img = ImageGrab.grab(xdisplay=os.environ.get('DISPLAY', ':0'))
                    img.save(shot)
                except Exception as e:
                    print('screenshot failed:', e)
            root.destroy()

        root.after(1800, _shot_and_close)

    root.mainloop()
    return 0


def main():
    cli_main()


if __name__ == '__main__':
    main()

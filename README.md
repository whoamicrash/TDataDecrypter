# TDataDecrypter

**TDataDecrypter.py** self-contained a dependency-light forensic/recovery tool for
**Telegram Desktop / AyuGram `tdata` folders**. It decrypts local storage, extracts and
validates every recoverable media file, reconstructs sliced videos, decodes cache
`file_id`s and usage timestamps, recovers account activity (searched peers, hashtags,
bots, video playback positions), and produces a clean text dump all offline, all in
one Python file.

> Works with plain (no-passcode) and passcode-protected tdata folders, including the
> old `key_datas` key format and the newer `key_datass` format. Unknown passcodes can
> be exported as a `$telegram$` hash for John the Ripper / hashcat.

---

## What it recovers

| Category | Details |
|---|---|
| **LocalKey** | Derived from `key_datas`/`key_datass` via `CreateLocalKey` (PBKDF2-HMAC-SHA512, 100 000 iterations in passcode mode, 1 iteration otherwise). Verified against `infoEncrypted`. |
| **Passcode hash export** | `--john` prints a `$telegram$2*100000*...` hash for offline cracking with John the Ripper (`--format=telegram`) or hashcat. |
| **Account profile** | Phone, username, service links (from decrypted settings + usertag). |
| **Account activity** | Top/recent peers from search suggestions (names, phones, usernames, ratings), sent/searched hashtags, recent bots, and media playback positions (the second a video was last stopped at). Output: `activity/activity.txt` + `activity.json`. |
| **Photos** | JPEG (structural validation + trailing-garbage trimming after last EOI), PNG, AVIF. Complete *and* partial (`.jpg.partial`) files. |
| **Videos** | MP4/MOV/WebM via full box-walk with 32/64-bit sizes; playable fragments kept as `.frag.mp4`. |
| **Video reconstruction** | `media_cache` slices (128 KB parts, 8 MB slots) reassembled by moov-heuristic: overlap-**VERIFIED** stitching, full-8MB-slot completion (**ASSUMED**), tail slots by size. Holes zero-filled — partial results stay playable. |
| **Stickers** | `.tgs` (first gzip member + Lottie-JSON structure check), WebP, WebM. |
| **Voice** | OGG/Opus with signature + page validation. |
| **Files** | GIF, PDF, MP3, WAV, SVG, SQLite and other sniffed formats. |
| **file_id recovery** | Cache keys are decoded into Telegram media IDs (the 19-digit int64 `document_id` / `photo_id`): files are named `voice_7916765197716291584.ogg`, `photo_123_x.jpg`, `video_456.mp4`. |
| **Timestamps** | `StoreWithTime.system` from the cache binlog restores each file's original caching time — applied as the file's mtime and recorded in `media_index.jsonl`. |
| **Texts** | Structured `QDataStream` (UTF-16BE) parsing + regex fallback (BE/LE/UTF-8), language scoring (EN/RU bigrams), CamelCase/hump analysis for sticker-pack names → clean `texts/messages.txt` + raw dump. |
| **Drafts & settings** | Drafts and self-serialized data from `map` files. |
| **AyuGram extras** | `ayudata.db` (SQLite: deleted/edited messages) dumped if present. |
| **Caches** | `TDEF` (lib_storage AES-CTR, 64-byte salt), binlog indexes (MultiStore/MultiRemove/MultiAccess with time tracking, XXH32 checksums), place-file layout (XX/xxxx buckets). |

Everything is deduplicated by SHA-256.

## Output layout

```
out/
├── photos/          # valid jpg/png/avif, named by file_id (image_1234567890123456789.jpg)
│   └── partial/     # truncated but viewable images
├── videos/          # mp4/mov/webm (full), named video_<document_id>.mp4
│   └── partial/     # playable fragments (.frag.mp4)
├── stickers/        # tgs / webp / webm
├── voice/           # ogg/opus, named voice_<document_id>.ogg
├── files/           # everything else that sniffed OK
├── texts/           # messages.txt (clean) + raw dump
├── activity/        # activity.txt + activity.json (peers, hashtags, bots,
│                    #   playback positions)
├── media_index.jsonl    # per-file: file_id, key kind, dc, content tag, size,
│                        #   store_time, use counter, place
├── ayu/             # ayudata.db dump (AyuGram only)
└── report.txt       # run summary
```

File mtimes are restored to the moment each media item was cached.

## Requirements

- Python **3.9+**
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) (AES)
- `tgcrypto` — *optional*, pure-Python AES-IGE fallback is built in

```bash
pip install pycryptodome
# optional speed-up:
pip install tgcrypto
```

No GUI toolkit required for CLI mode. The GUI uses `tkinter` (bundled with Python on
Windows/macOS; on Linux install `python3-tk`).

## Usage

### GUI

```bash
python TDataDecrypter.py
```

Pick the `tdata` directory, pick an output directory, press **Start**. If the key
fails without a passcode, the GUI will ask for one.

### CLI

```bash
python TDataDecrypter.py <path_to_tdata> <output_dir> [--passcode 1234]
```

Examples:

```bash
# no passcode
python TDataDecrypter.py "C:/tdata" ./out

# passcode-protected
python TDataDecrypter.py "C:/tdata" ./out --passcode 1234

# unknown passcode: export a hash for John the Ripper / hashcat
python TDataDecrypter.py "C:/tdata" --john > hash.txt
john --format=telegram hash.txt
```

### Self-test (54 internal checks, no tdata needed)

```bash
python TDataDecrypter.py --selftest
```

Verifies the crypto core against reference vectors (AES-IGE round-trips, XXH32 test
vectors, passcode-mode KDF, TDF format parsing) plus the cache-key decoder, peer-id
deserialization, activity parsers and the JtR hash format.

## How it works

1. **Key**: `key_datas`/`key_datass` → salt + encrypted key + encrypted info.
   `CreateLocalKey` = `PBKDF2-HMAC-SHA512(sha512(salt+pass+salt), 1|100000 iters, 256B)`.
   Correctness is proven by decrypting `infoEncrypted`.
2. **TDF files** (`TDF$` magic): 16-byte SHA1 prefix + AES-IGE payload, `u32 LE` length
   embedded in the length field, MD5 trailer.
3. **TDEF caches** (lib_storage): 64-byte salt, AES-CTR with
   `key = sha256(k[:128]‖salt[:16])`, `iv = sha256(k[128:]‖salt[16:32])[:16]`,
   SHA-256 header checksum.
4. **Places**: `XX/xxxx…` buckets derived by reverse-nibble hex of the file id;
   files decrypted with the cache key directly.
5. **media_cache**: 128 KB parts packed into 8 MB slices; header maps are either
   contiguous or complex (absolute offsets). Binlog lost? Orphan slices are salvaged
   and stitched by content overlap around the `moov` box.
6. **Cache keys**: `StorageCacheKey`/`bigFileBaseCacheKey` layouts are decoded into
   key kind + dc + media id (`document_id`, `photo_id`), giving every recovered file
   its Telegram-side 19-digit file_id; `StoreWithTime` records carry the caching time.
7. **Validation**: every output file passes a format-specific structural check
   (not just a magic-number sniff) before being placed into a category folder.

## Limitations

- Chat history is **not** stored in tdata (Telegram keeps it server-side) — expect
  drafts, names, and locally cached artifacts, not full conversations.
- file_id recovery and timestamps require a live `binlog` in the cache databases; if
  the binlog was lost, files are still recovered but without ids/times.
- Video reconstruction is heuristic: VERIFIED slices are byte-exact, ASSUMED ones are
  best-effort; unrecoverable holes are zero-filled.
- `ayudata.db` exists only if the tdata comes from AyuGram with its history module enabled.

## Legal / ethics

- For **non-commercial** use only — see [LICENSE](LICENSE) (PolyForm Noncommercial 1.0.0).
- Use **only on your own data** or data you are explicitly authorized to process.
- The author take no responsibility for misuse.

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE](LICENSE).

## Telegram
[@hackerebanatik](https://t.me/hackerebanatik )


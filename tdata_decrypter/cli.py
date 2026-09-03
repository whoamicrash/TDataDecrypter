import argparse
import os
import sys

from .constants import APP_TITLE
from .core import TDataDecrypter, locate_tdata
from .gui import run_gui
from .i18n import load_saved_lang, save_lang_cfg, set_lang, tr
from .keys import john_hash
from .selftest import selftest
from .ui import ConsoleUI, Options


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


def main():
    cli_main()

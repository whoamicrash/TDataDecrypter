import os
import shutil
import sqlite3

from .i18n import tr


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
                            "FROM DeletedMessage ORDER BY dialogId, messageId")
                for dlg, frm, mid, date, text, media in cur.fetchall():
                    rows_deleted += 1
                    f.write(f"dialog={dlg} from={frm} msg={mid} date={date}\n"
                            f"  text: {text!r}\n  media: {media}\n")
        if 'EditedMessage' in tables:
            with open(os.path.join(ayu_dir, 'edited_messages.txt'), 'w', encoding='utf-8') as f:
                cur.execute("SELECT dialogId, fromId, messageId, date, editDate, text "
                            "FROM EditedMessage ORDER BY dialogId, messageId, editDate")
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

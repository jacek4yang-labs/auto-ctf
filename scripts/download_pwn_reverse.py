"""Download PWN + REVERSE attachments (files[].download_url from the
browser-session enumeration). Resume-safe: skips existing non-empty files."""

import json
import os
import re
import time
import urllib.request


def slugify(s):
    s = re.sub(r'[\\/:*?"<>|\s\[\]()]+', '_', s)
    return s[:70]


def main():
    ok = skip = fail = 0
    for src, base in [('.tmp/buuctf-pwn-files.json', 'challenges/ctf2/buuctf/PWN'),
                      ('.tmp/buuctf-reverse-files.json', 'challenges/ctf2/buuctf/REVERSE')]:
        data = json.load(open(src, encoding='utf-8'))
        for c in data:
            if not c['files']:
                continue
            folder = f"{base}/{slugify(c['name'])}"
            os.makedirs(folder, exist_ok=True)
            meta = {'id': c['id'], 'name': c['name'], 'category': c['category']}
            json.dump(meta, open(f'{folder}/meta.json', 'w', encoding='utf-8'),
                      ensure_ascii=False, indent=1)
            for f in c['files']:
                ext = os.path.splitext(f['download_url'].split('?')[0])[1] or '.bin'
                dest = f"{folder}/files/{f['id'][:8]}{ext}"
                if os.path.exists(dest) and os.path.getsize(dest) > 0:
                    skip += 1
                    continue
                os.makedirs(folder + '/files', exist_ok=True)
                req = urllib.request.Request(f['download_url'],
                                             headers={'User-Agent': 'Mozilla/5.0'})
                for attempt in range(3):
                    try:
                        b = urllib.request.urlopen(req, timeout=60).read()
                        open(dest, 'wb').write(b)
                        ok += 1
                        break
                    except Exception:
                        time.sleep(1.5 * (attempt + 1))
                else:
                    fail += 1
        print(f'{src}: cumulative ok={ok} skip={skip} fail={fail}', flush=True)
    print(f'DONE downloaded={ok} skipped={skip} failed={fail}')


if __name__ == '__main__':
    main()

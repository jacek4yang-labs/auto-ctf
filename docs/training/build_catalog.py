"""Build challenge catalog from on-disk CTF2 challenge dirs -> catalog.json"""
import json, glob, os
from collections import Counter

cat = []
for base, ground in [('challenges/ctf2/buuctf', 'buuctf'),
                     ('challenges/ctf2/dasbook', 'dasbook'),
                     ('challenges/ctf2/n1book', 'n1book')]:
    for mf in glob.glob(f'{base}/*/*/meta.json') + glob.glob(f'{base}/*/*/*/meta.json'):
        d = os.path.dirname(mf)
        try:
            m = json.load(open(mf, encoding='utf-8'))
        except Exception:
            continue
        rj = os.path.join(d, 'solve', 'result.json')
        st = None
        if os.path.exists(rj):
            try:
                st = json.load(open(rj, encoding='utf-8')).get('status')
            except Exception:
                pass
        files = os.path.isdir(os.path.join(d, 'files')) and len(os.listdir(os.path.join(d, 'files'))) > 0
        cat.append({'name': m.get('name', ''), 'category': m.get('category', ''),
                    'difficulty': m.get('difficulty', ''), 'points': m.get('points', 0),
                    'ground': ground, 'dir': d.replace(os.sep, '/'),
                    'files': files, 'status': st or 'unattempted'})

json.dump(cat, open('docs/training/catalog.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('total:', len(cat))
by = Counter((x['ground'], x['category']) for x in cat)
for k, v in sorted(by.items()):
    print(k, v)

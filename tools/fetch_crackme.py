#!/usr/bin/env python3
"""fetch_crackme.py <id> <dir> - grab a crackme and unpack it.

<id> is the hex blob in the crackmes.one URL. Everything on the site is
zipped with the password "crackmes.one".
"""
import html
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

UA = 'Mozilla/5.0'
PASSWORD = 'crackmes.one'


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def metadata(cid: str) -> dict:
    page = get(f'https://crackmes.one/crackme/{cid}').decode('utf-8', 'replace')
    text = html.unescape(re.sub(r'<[^>]+>', '\n', page))
    fields = {}
    for label in ('Author', 'Language', 'Upload', 'Platform', 'Difficulty', 'Quality', 'Arch'):
        m = re.search(rf'{label}:\s*\n+\s*([^\n]+)', text)
        if m:
            fields[label] = m.group(1).strip()
    m = re.search(r'<title[^>]*>(.*?)</title>', page, re.S)
    if m:
        fields['Name'] = html.unescape(m.group(1)).replace('crackmes.one /', '').strip()
    m = re.search(r'Description\s*\n+\s*([^\n]+)', text)
    if m:
        fields['Description'] = m.group(1).strip()
    return fields


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cid, dest = sys.argv[1], Path(sys.argv[2])
    dest.mkdir(parents=True, exist_ok=True)

    for k, v in metadata(cid).items():
        print(f'{k:12} {v}')

    zip_path = dest / f'{cid}.zip'
    zip_path.write_bytes(get(f'https://crackmes.one/download/crackme/{cid}'))
    print(f'\nsaved {zip_path} ({zip_path.stat().st_size} bytes)')

    subprocess.run(['unzip', '-P', PASSWORD, '-o', str(zip_path), '-d', str(dest)], check=True)
    for f in sorted(dest.iterdir()):
        if f.suffix != '.zip':
            f.chmod(0o644)  # don't leave the sample executable
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

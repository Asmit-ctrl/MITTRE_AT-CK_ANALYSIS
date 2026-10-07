"""Download real Splunk ATT&CK logs at an immutable revision; keep provenance."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'data' / 'samples'
HEADERS = {'User-Agent': 'Shiftline-prototype', 'Accept': 'application/vnd.github+json'}

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=60) as response:
        return response.read()

def main():
    DEST.mkdir(parents=True, exist_ok=True)
    revision = json.loads(get('https://api.github.com/repos/splunk/attack_data/commits/master'))['sha']
    paths = [
        ('T1059.001', 'PowerShell execution', 'datasets/attack_techniques/T1059.001'),
        ('T1003.001', 'Credential access', 'datasets/attack_techniques/T1003.001'),
        ('T1070', 'Indicator removal', 'datasets/attack_techniques/T1070'),
    ]
    tree = json.loads(get(f'https://api.github.com/repos/splunk/attack_data/git/trees/{revision}?recursive=1'))
    entries = []
    for technique, name, prefix in paths:
        candidates = [n for n in tree['tree'] if n['type'] == 'blob' and n['path'].startswith(prefix + '/') and n['path'].endswith('.log') and 'sysmon' in n['path'].lower()]
        candidates.sort(key=lambda n: (not ('atomic_red_team' in n['path'].lower()), n.get('size', 0), n['path']))
        for candidate in candidates:
            path = candidate['path']
            source = f'https://media.githubusercontent.com/media/splunk/attack_data/{revision}/{path}'
            try:
                with urllib.request.urlopen(urllib.request.Request(source, headers=HEADERS), timeout=60) as response:
                    raw = response.read(15_000_001)
                if len(raw) > 15_000_000:
                    continue
                if raw.startswith(b'version https://git-lfs'):
                    continue
                filename = technique + '.log'
                (DEST / filename).write_bytes(raw)
                entries.append({'id': technique, 'name': name, 'filename': filename, 'repository': 'splunk/attack_data', 'revision': revision, 'path': path, 'url': f'https://github.com/splunk/attack_data/blob/{revision}/{path}', 'download_url': source, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
                print(f'{technique}: downloaded {len(raw):,} bytes from {path}')
                break
            except Exception as exc:
                print(f'Skipped {path}: {type(exc).__name__}')
    (DEST / 'manifest.json').write_text(json.dumps(entries, indent=2), encoding='utf-8')
    (DEST / 'LICENSE.splunk').write_bytes(get(f'https://raw.githubusercontent.com/splunk/attack_data/{revision}/LICENSE'))
    if not entries:
        raise RuntimeError('No actual log data downloaded')

if __name__ == '__main__':
    main()

"""Verify dataset origin against local pinned source bytes, never a client URL."""
import hashlib
import json
from pathlib import Path
from .ingestion import split_batch

ROOT = Path(__file__).resolve().parents[1]

def digest(text): return hashlib.sha256(text.encode('utf-8')).hexdigest()

def source_for(raw, sample_id=None):
    source = {'kind':'analyst_submission','submission_sha256':digest(raw)}
    if not sample_id: return source
    path = ROOT/'data'/'samples'/'manifest.json'
    entries = json.loads(path.read_text(encoding='utf-8')) if path.exists() else []
    entry = next((x for x in entries if x['id']==sample_id),None)
    if not entry: raise ValueError('Unknown sample source. Reload a sample or submit without a sample claim.')
    file_bytes = (ROOT/'data'/'samples'/entry['filename']).read_bytes()
    if hashlib.sha256(file_bytes).hexdigest()!=entry['sha256']: raise ValueError('Sample integrity check failed.')
    logs = split_batch(file_bytes.decode('utf-8').replace('\r\n','\n'))
    if not any(raw==''.join(logs[:count]) for count in [1,20,100,3000]):
        raise ValueError('Sample was changed. Reload it or submit as an analyst-provided log.')
    return {**source,'kind':'verified_splunk_sample','repository':entry['repository'],'revision':entry['revision'],
            'path':entry['path'],'url':entry['url'],'dataset_sha256':entry['sha256']}

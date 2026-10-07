"""Keep original evidence; extract only a few fields for conservative grouping."""
import hashlib
import json
import re
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

MAX_INPUT = 8_000_000
MAX_ALERTS = 3000
MAX_LOG = 100_000
ASSET_WEIGHTS = {'low':15, 'standard':35, 'high':70, 'critical':100}
SEVERITY_WEIGHTS = {'unknown':30, 'low':20, 'medium':45, 'high':70, 'critical':90}

def score(severity, asset):
    return round(.65 * SEVERITY_WEIGHTS.get(severity,30) + .35 * ASSET_WEIGHTS[asset])

def explain_score(severity,asset,analyzed=False):
    severity_weight=SEVERITY_WEIGHTS.get(severity,30)
    return {'severity':severity,'severity_weight':severity_weight,'severity_contribution':round(.65*severity_weight,2),
            'asset':asset,'asset_weight':ASSET_WEIGHTS[asset],'asset_contribution':round(.35*ASSET_WEIGHTS[asset],2),
            'score':score(severity,asset),'severity_source':'AI assessment; analyst review required' if analyzed else 'Initial log heuristics; unverified',
            'formula':'round(0.65 × severity + 0.35 × asset criticality)','alert_count_affects_score':False,
            'grouping_rule':'Same host, user and candidate behavior; maximum one-hour event span. Unknown fields stay separate.'}

def split_batch(raw):
    """Return exact source slices, not reserialized JSON or trimmed lines."""
    stripped = raw.lstrip()
    if stripped.startswith('['):
        decoder = json.JSONDecoder()
        pos = len(raw) - len(stripped) + 1
        slices = []
        while True:
            while pos < len(raw) and raw[pos].isspace(): pos += 1
            if pos >= len(raw): raise ValueError('Incomplete JSON array.')
            if raw[pos] == ']':
                if raw[pos+1:].strip(): raise ValueError('Unexpected content after the JSON array.')
                break
            start = pos
            obj, pos = decoder.raw_decode(raw, pos)
            if not isinstance(obj, dict): raise ValueError('Batch JSON must contain alert objects.')
            slices.append(raw[start:pos])
            while pos < len(raw) and raw[pos].isspace(): pos += 1
            if pos < len(raw) and raw[pos] == ',':
                pos += 1
                if raw[pos:].lstrip().startswith(']'): raise ValueError('Trailing JSON comma.')
            elif pos >= len(raw) or raw[pos] != ']': raise ValueError('Expected a comma between alerts.')
        return slices
    if stripped.startswith('<') and '<Event' in raw and '</Event>' in raw:
        # Splunk Sysmon events are whole XML documents, often one per line.
        slices, pos = [], 0
        for match in re.finditer(r'</Event>', raw):
            end = match.end()
            while end < len(raw) and raw[end] in '\r\n': end += 1
            slices.append(raw[pos:end])
            pos = end
        if raw[pos:].strip(): raise ValueError('Incomplete XML event at the end of the batch.')
        return slices
    lines = raw.splitlines(keepends=True)
    if not all(not line.strip() or isinstance(json.loads(line),dict) for line in lines):
        raise ValueError('Use a JSON array, NDJSON alert objects, or complete Sysmon XML events for batches.')
    return [line for line in lines if line.strip()]

def extract(raw, host_override=''):
    fields = {}
    behavior=raw
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            if obj.get('demo') is True:
                behavior=json.dumps({k:v for k,v in obj.items() if k not in {'source_url','source_sha256','replay_note','category','original_timestamp'}})
            fields = {str(k).lower():v for k,v in obj.items() if isinstance(v,(str,int,float))}
            def flatten(prefix,value,depth=0):
                if isinstance(value,dict) and depth<3:
                    for key,child in value.items():flatten(prefix+'.'+str(key).lower(),child,depth+1)
                elif isinstance(value,(str,int,float)):fields[prefix]=value
            for key in ['source','destination','host','user','process','event']:
                if isinstance(obj.get(key),dict):flatten(key,obj[key])
            if isinstance(obj.get('EventData'),dict): fields.update({k.lower():v for k,v in obj['EventData'].items()})
            # Splunk exports often wrap the original event in _raw.
            if isinstance(obj.get('_raw'),str): fields.update(extract(obj['_raw'])['fields'])
    except (ValueError, TypeError):
        if '<Event' in raw and '<!DOCTYPE' not in raw and '<!ENTITY' not in raw:
            try:
                root = ET.fromstring(raw.strip())
                for el in root.iter():
                    tag = el.tag.rsplit('}',1)[-1]
                    if tag == 'Data' and el.get('Name'): fields[el.get('Name').lower()] = el.text or ''
                    elif tag in {'Computer','EventID'}: fields[tag.lower()] = el.text or ''
                    elif tag == 'TimeCreated': fields['timestamp'] = el.get('SystemTime','')
            except ET.ParseError: pass
        else:
            for match in re.finditer(r'\b(host|hostname|computer|dest|user|timestamp|severity|src_ip|dest_ip)\s*[=:]\s*(?:"([^"]*)"|([^\s,]+))',raw,re.I):
                fields[match[1].lower()] = match[2] or match[3]
    host = host_override.strip() or str(next((fields[k] for k in ['computer','host','host.name','hostname','devicehostname','dest','dvc','aid'] if fields.get(k)), 'unknown'))
    user = str(fields.get('user',fields.get('user.name',fields.get('username',fields.get('usersid','unknown')))))
    stamp = str(next((fields[k] for k in ['timestamp','utctime','_time','time','@timestamp'] if fields.get(k)),''))
    try:
        numeric=float(stamp) if re.fullmatch(r'\d+(?:\.\d+)?',stamp) else None
        dt = datetime.fromtimestamp(numeric/1000 if numeric and numeric>100_000_000_000 else numeric, timezone.utc) if numeric is not None else datetime.fromisoformat(stamp.replace('Z','+00:00'))
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        epoch = dt.timestamp()
    except (ValueError,OverflowError,OSError): epoch = None
    lower = behavior.lower()
    hints = list(dict.fromkeys(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', behavior)))[:6]
    severity, title = 'unknown', 'Unclassified security event'
    if 'lsass' in lower and any(x in lower for x in ['dump','mimikatz','procdump']):
        hints.insert(0,'T1003.001'); severity, title = 'high', 'Possible LSASS credential dumping'
    elif any(x in lower for x in ['wevtutil cl','clear-eventlog','cleareventlog']):
        hints.insert(0,'T1070.001'); severity, title = 'high', 'Possible Windows event-log clearing'
    elif 'powershell' in lower or 'pwsh.exe' in lower:
        hints.insert(0,'T1059.001'); severity, title = 'low', 'PowerShell execution observed'
        if any(x in lower for x in ['-enc','-encodedcommand','invoke-expression','iex (','downloadstring','-windowstyle hidden']):
            severity, title = 'high', 'Suspicious PowerShell execution'
    elif 'cmd.exe' in lower:
        hints.insert(0,'T1059.003'); severity, title = 'low', 'Windows command-shell activity'
    provided_severity = str(fields.get('severity','')).lower()
    if provided_severity in SEVERITY_WEIGHTS and (severity=='unknown' or SEVERITY_WEIGHTS[provided_severity] > SEVERITY_WEIGHTS[severity]): severity = provided_severity
    hints = list(dict.fromkeys(hints))[:6]
    return {'host':host[:160], 'user':user[:160], 'timestamp':stamp[:80], 'epoch':epoch, 'hints':hints, 'severity':severity, 'title':title, 'fields':fields,
            'sha256':hashlib.sha256(raw.encode('utf-8')).hexdigest()}

def validate_input(raw, mode):
    if not raw.strip(): raise ValueError('Paste a log first.')
    if len(raw.encode('utf-8')) > MAX_INPUT: raise ValueError('A submission can contain up to 8 MB.')
    try:
        logs = [raw] if mode == 'single' else split_batch(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError('Batch format invalid. Use a JSON array, NDJSON, or complete Sysmon XML events.') from exc
    if not logs or len(logs)>MAX_ALERTS: raise ValueError('A batch must contain 1–3,000 alerts.')
    if any(len(log)>MAX_LOG for log in logs): raise ValueError('Each alert can contain up to 100,000 characters. Use Batch for multiple events.')
    return logs

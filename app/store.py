import json
import hashlib
import math
import os
import sqlite3
import time
import uuid
from contextvars import ContextVar
from contextlib import contextmanager
from pathlib import Path
from .ingestion import extract, score, explain_score, SEVERITY_WEIGHTS, ASSET_WEIGHTS
from . import observations

def audit_hash(event,previous):
    payload={key:event[key] for key in ['incident_id','action','analyst','note','created','metadata']}
    return hashlib.sha256((previous+json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False)).encode()).hexdigest()

def append_audit(conn,incident_id,action,analyst,note,metadata=None):
    last=conn.execute('SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1').fetchone()
    previous=last[0] if last else '0'*64
    event={'incident_id':incident_id,'action':action,'analyst':analyst,'note':note,'created':time.time(),
           'metadata':json.dumps(metadata or {},sort_keys=True,separators=(',',':'),ensure_ascii=False)}
    checksum=audit_hash(event,previous)
    conn.execute('''INSERT INTO audit(incident_id,action,analyst,note,created,metadata,prev_hash,event_hash)
        VALUES (?,?,?,?,?,?,?,?)''',tuple(event[k] for k in ['incident_id','action','analyst','note','created','metadata'])+(previous,checksum))
    return checksum

ROOT = Path(__file__).resolve().parents[1]

WORKSPACE = ContextVar('shiftline_workspace', default='live')
def db_path():
    scope=WORKSPACE.get()
    return ROOT / 'data' / (scope+'.db') if scope in {'demo','lab'} else Path(os.getenv('TRIAGE_DB',str(ROOT / 'data' / 'triage.db')))

@contextmanager
def connection():
    db_path().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally: conn.close()

def initialize():
    with connection() as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS submissions(id TEXT PRIMARY KEY, raw TEXT NOT NULL, mode TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS incidents(
            id TEXT PRIMARY KEY, title TEXT NOT NULL, host TEXT NOT NULL, user TEXT NOT NULL,
            asset TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL, correlation TEXT NOT NULL,
            first_event REAL, last_event REAL, created REAL NOT NULL, updated REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', decision TEXT NOT NULL DEFAULT 'unreviewed',
            analysis TEXT, analysis_seconds REAL, first_review REAL, revision INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS incident_correlation ON incidents(correlation,last_event);
        CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, submission_id TEXT NOT NULL REFERENCES submissions(id),
            incident_id TEXT NOT NULL REFERENCES incidents(id), raw TEXT NOT NULL, sha256 TEXT NOT NULL, extracted TEXT NOT NULL, created REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS alert_incident ON alerts(incident_id);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT REFERENCES incidents(id),
            action TEXT NOT NULL, analyst TEXT NOT NULL, note TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')
        migrations={'submissions':{'source':'TEXT','ingest_seconds':'REAL','raw_sha256':'TEXT'},
                    'incidents':{'resolved_at':'REAL','ai_classification':'TEXT','approved_mappings':"TEXT NOT NULL DEFAULT '[]'",'disposition':"TEXT NOT NULL DEFAULT 'unknown'",'assigned_to':"TEXT NOT NULL DEFAULT ''",'business_state':"TEXT NOT NULL DEFAULT 'review_required'"},
                    'audit':{'metadata':"TEXT NOT NULL DEFAULT '{}'",'prev_hash':'TEXT','event_hash':'TEXT'}}
        for table,columns in migrations.items():
            existing={r['name'] for r in conn.execute(f'PRAGMA table_info({table})')}
            for name,definition in columns.items():
                if name not in existing: conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
        conn.executescript('''CREATE TABLE IF NOT EXISTS analysis_runs(
            id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),created REAL NOT NULL,
            duration REAL NOT NULL,status TEXT NOT NULL,snapshot TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS runs_incident ON analysis_runs(incident_id,created);''')
        # Existing history is explicitly marked as backfilled, not retroactively attested.
        previous='0'*64
        for event in conn.execute('SELECT * FROM audit ORDER BY id').fetchall():
            if event['event_hash'] is None:
                item=dict(event);item['metadata']='{"legacy_backfilled":true}'
                checksum=audit_hash(item,previous)
                conn.execute('UPDATE audit SET metadata=?,prev_hash=?,event_hash=? WHERE id=?',(item['metadata'],previous,checksum,event['id']))
                previous=checksum
            else: previous=event['event_hash']
        conn.executescript('''CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
            BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
            BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;''')
        # A terminated process never leaves an incident permanently stuck.
        conn.execute("UPDATE incidents SET status='failed' WHERE status='analyzing'")
        observations.initialize(conn)

def uid(): return uuid.uuid4().hex

def ingest(raw, logs, mode, asset, host, source=None):
    started=time.perf_counter()
    now, submission = time.time(), uid()
    incident_ids = []
    with connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('INSERT INTO submissions(id,raw,mode,created,source,raw_sha256) VALUES (?,?,?,?,?,?)',
                     (submission,raw,mode,now,json.dumps(source or {}),hashlib.sha256(raw.encode()).hexdigest()))
        for log in logs:
            fields = extract(log, host)
            events=observations.normalize(log,host)
            if fields['title']=='Unclassified security event' and events:
                fields['title']=events[0]['label'] if events[0]['label']!='Unclassified security event' else 'Security activity awaiting analysis'
            if len(events)==1:
                fields.update({key:events[0][key] for key in ['host','user','epoch','timestamp']})
            elif events:
                hosts={e['host'] for e in events if e['host']!='unknown'}
                users={e['user'] for e in events if e['user']!='unknown'}
                if len(hosts)==1:fields['host']=next(iter(hosts))
                if len(users)==1:fields['user']=next(iter(users))
                epochs=[e['epoch'] for e in events if e['epoch'] is not None]
                if epochs:fields['epoch']=min(epochs)
            # Only same host, user, behavior and <=1-hour total event span correlate.
            # Unknown identity/behavior/timestamp stays separate; avoids huge garbage groups.
            correlatable = fields['host'] != 'unknown' and fields['epoch'] is not None and bool(fields['hints'])
            key = json.dumps([fields['host'].lower(),fields['user'].lower(),fields['hints'][0] if fields['hints'] else 'unknown'])
            candidate = observations.correlate(conn,events)
            if correlatable and candidate is None and not any(e['process_id'] for e in events):
                candidate = conn.execute('''SELECT * FROM incidents WHERE correlation=? AND decision='unreviewed'
                    AND status != 'analyzing' AND abs(first_event-?)<=3600 AND abs(last_event-?)<=3600
                    ORDER BY created DESC LIMIT 1''',(key,fields['epoch'],fields['epoch'])).fetchone()
            if candidate:
                incident_id = candidate['id']
                criticality = max([asset,candidate['asset']],key=ASSET_WEIGHTS.get)
                severity = max([fields['severity'],candidate['severity']],key=SEVERITY_WEIGHTS.get)
                conn.execute('''UPDATE incidents SET asset=?,severity=?,score=?, first_event=min(first_event,?),
                    last_event=max(last_event,?),updated=?,status='pending',analysis=NULL,ai_classification=NULL,analysis_seconds=NULL,revision=revision+1 WHERE id=?''',
                    (criticality,severity,score(severity,criticality),fields['epoch'],fields['epoch'],now,incident_id))
            else:
                incident_id = uid()
                conn.execute('''INSERT INTO incidents(id,title,host,user,asset,severity,score,correlation,first_event,last_event,created,updated)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',(incident_id,fields['title'],fields['host'],fields['user'],asset,fields['severity'],score(fields['severity'],asset),key,fields['epoch'],fields['epoch'],now,now))
            alert_id=uid()
            conn.execute('INSERT INTO alerts VALUES (?,?,?,?,?,?,?)',(alert_id,submission,incident_id,log,fields['sha256'],json.dumps(fields),now))
            observations.insert_events(conn,alert_id,incident_id,events)
            epochs=[e['epoch'] for e in events if e['epoch'] is not None]
            if epochs:conn.execute('UPDATE incidents SET first_event=?,last_event=? WHERE id=?',
                                  (min([fields['epoch']]+epochs+([candidate['first_event']] if candidate else [])),max(epochs+([candidate['last_event']] if candidate else [])),incident_id))
            if incident_id not in incident_ids: incident_ids.append(incident_id)
        duration=time.perf_counter()-started
        conn.execute('UPDATE submissions SET ingest_seconds=? WHERE id=?',(duration,submission))
        append_audit(conn,None,'ingestion','system',f'{len(logs)} alerts ingested into {len(incident_ids)} incidents.',
                     {'submission_id':submission,'source':source or {},'asset_criticality':asset,'host_override':host,'alert_count':len(logs),'incident_ids':incident_ids,'ingest_seconds':duration})
        from .investigation import refresh_risk
        for incident_id in incident_ids:refresh_risk(conn,incident_id)
        if conn.execute('SELECT 1 FROM benign_rules LIMIT 1').fetchone():
            critical=conn.execute("SELECT host,epoch FROM observed_events WHERE alert_id IN (SELECT id FROM alerts WHERE submission_id=?) AND kind IN ('credential_access','log_clear')",(submission,)).fetchall()
            affected=set()
            for event in critical:
                if event['epoch'] is not None:
                    affected.update(r[0] for r in conn.execute('SELECT DISTINCT incident_id FROM observed_events WHERE host=? COLLATE NOCASE AND epoch BETWEEN ? AND ?',
                                    (event['host'],event['epoch']-3600,event['epoch']+3600)))
            for incident_id in affected:refresh_risk(conn,incident_id)
    return {'submission_id':submission,'alert_count':len(logs),'incident_count':len(incident_ids),'incident_ids':incident_ids,'ingest_seconds':duration}

def unpack(row):
    result = dict(row)
    result['analysis'] = json.loads(result['analysis']) if result.get('analysis') else None
    result['ai_classification']=json.loads(result['ai_classification']) if result.get('ai_classification') else None
    result['approved_mappings']=json.loads(result.get('approved_mappings') or '[]')
    result.pop('correlation',None)
    return result

def list_incidents(filter=None,limit=None,offset=0):
    with connection() as conn:
        condition="WHERE i.decision='unreviewed'" if filter=='pending' else "WHERE i.decision!='unreviewed'" if filter=='reviewed' else "WHERE i.resolved_at IS NULL" if filter=='open' else "WHERE i.decision='escalated'" if filter=='escalated' else ''
        query=f'''SELECT i.*,count(a.id) AS alert_count FROM incidents i JOIN alerts a ON a.incident_id=i.id {condition}
            GROUP BY i.id ORDER BY i.score DESC, CASE WHEN i.decision='unreviewed' THEN 0 ELSE 1 END, i.created DESC'''
        rows=conn.execute(query+(' LIMIT ? OFFSET ?' if limit else ''),(limit,offset) if limit else ()).fetchall()
        results = []
        for row in rows:
            result = unpack(row)
            criticalities=[r[0] for r in conn.execute('''SELECT DISTINCT json_extract(c.data,'$.criticality')
                FROM context_records c JOIN observed_events e ON c.entity=lower(e.host)
                WHERE c.kind='asset' AND e.incident_id=?''',(result['id'],))]
            result['asset']=max([result['asset']]+[x for x in criticalities if x in ASSET_WEIGHTS],key=ASSET_WEIGHTS.get)
            brief=result.pop('analysis')
            result['has_analysis'] = bool(brief)
            result['confidence']=brief.get('confidence','unknown') if brief and result['status']=='ready' else (result.get('ai_classification') or {}).get('confidence','unknown')
            result['attack_type']=brief.get('mappings',[{}])[0].get('technique_id','') if brief and brief.get('mappings') else result['title']
            result['risk_band']='Critical' if result['score']>=80 else 'High' if result['score']>=60 else 'Medium' if result['score']>=40 else 'Low'
            results.append(result)
        return results

def detail(incident_id):
    with connection() as conn:
        row = conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row: return None
        result = unpack(row)
        result['alerts'] = [dict(r) for r in conn.execute('SELECT id,sha256,extracted,length(raw) AS characters FROM alerts WHERE incident_id=? ORDER BY created,id',(incident_id,))]
        for item in result['alerts']: item['extracted'] = json.loads(item['extracted'])
        result['alert_count'] = len(result['alerts'])
        result['risk_explanation']=explain_score(result['severity'],result['asset'],bool(result['analysis']))
        result['sources']=[dict(r) for r in conn.execute('''SELECT DISTINCT s.id,s.source,s.raw_sha256,s.ingest_seconds
            FROM submissions s JOIN alerts a ON a.submission_id=s.id WHERE a.incident_id=?''',(incident_id,))]
        for source in result['sources']: source['source']=json.loads(source['source'] or '{}')
        result['analysis_history']=[dict(r) for r in conn.execute('SELECT id,created,duration,status FROM analysis_runs WHERE incident_id=? ORDER BY created DESC LIMIT 20',(incident_id,))]
        result['audit'] = [dict(r) for r in conn.execute('SELECT action,analyst,note,created FROM audit WHERE incident_id=? ORDER BY id DESC LIMIT 30',(incident_id,))]
        return result

def metrics():
    with connection() as conn:
        row = conn.execute('''SELECT count(*) AS incidents, sum(CASE WHEN decision='unreviewed' THEN 1 ELSE 0 END) AS pending,
          sum(CASE WHEN first_review IS NOT NULL THEN 1 ELSE 0 END) AS reviewed,
          avg(CASE WHEN first_review IS NOT NULL THEN first_review-created END) AS mean_triage_seconds,
          avg(analysis_seconds) AS mean_analysis_seconds FROM incidents''').fetchone()
        result = dict(row)
        result['pending'] = result['pending'] or 0
        result['reviewed'] = result['reviewed'] or 0
        result['alerts'] = conn.execute('SELECT count(*) FROM alerts').fetchone()[0]
        baseline = conn.execute("SELECT value FROM settings WHERE key='baseline_seconds'").fetchone()
        result['baseline_seconds'] = float(baseline[0]) if baseline else None
        result['reduction_percent'] = round((1-result['mean_triage_seconds']/result['baseline_seconds'])*100,1) if result['reviewed'] and baseline else None
        resolutions=conn.execute('SELECT count(*) AS resolved,avg(resolved_at-created) AS mean_resolution_seconds FROM incidents WHERE resolved_at IS NOT NULL').fetchone()
        result.update(dict(resolutions))
        resolution_baseline=conn.execute("SELECT value FROM settings WHERE key='resolution_baseline_seconds'").fetchone()
        result['resolution_baseline_seconds']=float(resolution_baseline[0]) if resolution_baseline else None
        result['resolution_reduction_percent']=round((1-result['mean_resolution_seconds']/result['resolution_baseline_seconds'])*100,1) if result['resolved'] and resolution_baseline else None
        durations=[r[0] for r in conn.execute("SELECT duration FROM analysis_runs WHERE status='success' ORDER BY duration")]
        result['analysis_runs']=conn.execute('SELECT count(*) FROM analysis_runs').fetchone()[0]
        result['failed_analysis_runs']=conn.execute("SELECT count(*) FROM analysis_runs WHERE status='failed'").fetchone()[0]
        result['analysis_p50_seconds']=durations[math.ceil(len(durations)*.5)-1] if durations else None
        result['analysis_p95_seconds']=durations[math.ceil(len(durations)*.95)-1] if durations else None
        result['mean_ingest_seconds']=conn.execute('SELECT avg(ingest_seconds) FROM submissions').fetchone()[0]
        result['analysis_concurrency_limit']=2
        result['open_incidents']=conn.execute('SELECT count(*) FROM incidents WHERE resolved_at IS NULL').fetchone()[0]
        result['escalations']=conn.execute("SELECT count(*) FROM incidents WHERE decision='escalated'").fetchone()[0]
        result['closed_benign']=conn.execute("SELECT count(*) FROM incidents WHERE resolved_at IS NOT NULL AND disposition IN ('benign_trigger','false_positive')").fetchone()[0]
        return result

def verify_integrity():
    problems=[];previous='0'*64
    with connection() as conn:
        events=conn.execute('SELECT * FROM audit ORDER BY id').fetchall()
        for event in events:
            if event['prev_hash']!=previous or audit_hash(event,previous)!=event['event_hash']: problems.append(f'audit:{event["id"]}')
            previous=event['event_hash'] or ''
        alerts=conn.execute('SELECT id,raw,sha256 FROM alerts').fetchall()
        for alert in alerts:
            if hashlib.sha256(alert['raw'].encode()).hexdigest()!=alert['sha256']: problems.append(f'alert:{alert["id"]}')
        for submission in conn.execute('SELECT id,raw,raw_sha256 FROM submissions WHERE raw_sha256 IS NOT NULL'):
            if hashlib.sha256(submission['raw'].encode()).hexdigest()!=submission['raw_sha256']: problems.append(f'submission:{submission["id"]}')
        run_hashes={json.loads(e['metadata']).get('run_id'):json.loads(e['metadata']).get('snapshot_sha256') for e in events if e['action'] in {'analysis','analysis_failed'}}
        for run in conn.execute('SELECT id,snapshot FROM analysis_runs'):
            if hashlib.sha256(run['snapshot'].encode()).hexdigest()!=run_hashes.get(run['id']): problems.append(f'analysis_run:{run["id"]}')
    return {'ok':not problems,'events_checked':len(events),'alerts_checked':len(alerts),'chain_head':previous,'problems':problems,
            'scope':'Local tamper-evidence; no external anchor or authenticated analyst identity.'}

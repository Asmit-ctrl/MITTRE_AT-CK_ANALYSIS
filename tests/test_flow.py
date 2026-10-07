import hashlib
import json
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app import analysis, store
from app.main import app
from app.ingestion import split_batch, score, extract

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('TRIAGE_DB',str(tmp_path/'test.db'))
    with TestClient(app) as c: yield c

def ingest(client,raw,**kwargs):
    r=client.post('/api/ingest',json={'raw':raw,**kwargs})
    assert r.status_code==200,r.text
    return r.json()

def test_raw_preservation_and_hash(client):
    raw=' \tanything <script>alert(1)</script>\r\n  host=server-a\nइवेंट\n '
    result=ingest(client,raw)
    incident=client.get('/api/incidents/'+result['incident_ids'][0]).json()
    alert=client.get('/api/alerts/'+incident['alerts'][0]['id']+'/raw').json()
    assert alert['raw']==raw
    assert alert['sha256']==hashlib.sha256(raw.encode()).hexdigest()
    assert client.get('/api/submissions/'+result['submission_id']+'/raw').text==raw

def test_json_array_exact_slices():
    raw=' [ { "host" : "a", "message" : "x" },\n{ "host": "b" } ] '
    assert split_batch(raw)==['{ "host" : "a", "message" : "x" }','{ "host": "b" }']
    with pytest.raises(ValueError): split_batch('[{"a":1},]')
    with pytest.raises(ValueError): split_batch('[{"a":1}] rubbish')

def test_batch_grouping_and_asset_priority(client):
    # Unit fixtures verify boundaries; no synthetic dataset is shipped.
    records=[{'host':'a','user':'x','timestamp':f'2026-10-07T10:{minute:02d}:00Z','message':'powershell.exe -NoP'} for minute in [0,20,40]]
    records += [{'host':'b','user':'x','timestamp':'2026-10-07T10:00:00Z','message':'powershell.exe'},
                {'host':'a','user':'x','timestamp':'2026-10-07T12:00:00Z','message':'powershell.exe'}]
    result=ingest(client,json.dumps(records),mode='batch')
    assert result['alert_count']==5
    assert result['incident_count']==3
    items=client.get('/api/incidents').json()
    assert sorted(x['alert_count'] for x in items)==[1,1,3]
    target=next(x for x in items if x['host']=='b')
    updated=client.patch('/api/incidents/'+target['id']+'/asset',json={'asset':'critical','revision':target['revision']})
    assert updated.status_code==200
    assert client.get('/api/incidents').json()[0]['host']=='b'
    assert score('high','critical')>score('high','low')

def test_unknown_events_do_not_overgroup(client):
    result=ingest(client,'{"message":"something"}\n{"message":"something else"}\n',mode='batch')
    assert result['incident_count']==2

def test_review_timing_audit_and_stale_revision(client):
    result=ingest(client,'host=test powershell.exe')
    iid=result['incident_ids'][0]
    before=client.get('/api/incidents/'+iid).json()
    assert client.get('/api/metrics').json()['reduction_percent'] is None
    review={'decision':'escalated','analyst':'Test analyst','note':'Needs investigation','revision':before['revision']}
    answer=client.post('/api/incidents/'+iid+'/review',json=review)
    assert answer.status_code==200
    assert answer.json()['audit'][0]['analyst']=='Test analyst'
    first=answer.json()['first_review']
    assert client.post('/api/incidents/'+iid+'/review',json=review).status_code==409
    review.update(decision='confirmed',revision=answer.json()['revision'])
    assert client.post('/api/incidents/'+iid+'/review',json=review).json()['first_review']==first
    client.put('/api/baseline',json={'minutes':8})
    metrics=client.get('/api/metrics').json()
    assert metrics['reviewed']==1 and metrics['mean_triage_seconds']>=0
    assert metrics['reduction_percent'] is not None
    assert 'Test analyst' in client.get('/api/handoff').text

def test_reviewed_incidents_do_not_receive_events(client):
    raw='{"host":"a","user":"b","timestamp":"2026-10-07T10:00:00Z","message":"powershell.exe"}'
    first=ingest(client,raw)['incident_ids'][0]
    client.post('/api/incidents/'+first+'/review',json={'decision':'escalated','analyst':'Test','note':'Investigate','revision':1})
    assert ingest(client,raw)['incident_ids'][0]!=first

def test_model_mappings_require_graph_id_and_exact_quote(monkeypatch):
    raw='host=a powershell.exe -NoP'
    values=iter([analysis.RetrievalPlan(technique_ids=['T1059.001']),analysis.Brief(title='Suspicious shell',summary='Shell observed.',severity='high',confidence='medium',mappings=[
        analysis.Mapping(technique_id='T1059.001',reason='Shell',evidence_quote='powershell.exe'),
        analysis.Mapping(technique_id='T1003.001',reason='Invented',evidence_quote='powershell.exe'),
        analysis.Mapping(technique_id='T1059.001',reason='Invented quote',evidence_quote='mimikatz')],next_steps=['Verify the process.'],uncertainty='Intent is unknown.')])
    monkeypatch.setattr(analysis,'ask',lambda *a,**k: next(values))
    monkeypatch.setattr(analysis,'retrieve',lambda plan:[{'id':'T1059.001','name':'PowerShell'}])
    result=analysis.analyze([raw],[],'critical')
    assert len(result['mappings'])==1 and result['rejected_mappings']==2

def test_literal_reference_keeps_original_quote(monkeypatch):
    raw='{"host":"a","message":"PowerShell.exe -WindowStyle Hidden"}'
    outputs=iter([analysis.RetrievalPlan(technique_ids=['T1059.001']),analysis.Brief(title='Shell observed',summary='Investigate intent.',severity='medium',confidence='medium',mappings=[analysis.Mapping(technique_id='T1059.001',reason='Shell execution',evidence_ref='log1-e1')],next_steps=['Review parent process.'],uncertainty='Intent unconfirmed.')])
    def ask(system,payload,schema,max_tokens):
        if schema is analysis.Brief:
            assert payload['raw_logs']==[raw]
            assert payload['literal_evidence']['log1-e1']=='PowerShell.exe -WindowStyle Hidden'
        return next(outputs)
    monkeypatch.setattr(analysis,'ask',ask)
    monkeypatch.setattr(analysis,'retrieve',lambda plan:[{'id':'T1059.001'}])
    result=analysis.analyze([raw],[],'standard')
    assert result['mappings'][0]['evidence_quote']=='PowerShell.exe -WindowStyle Hidden'
    assert result['rejected_mappings']==0

def test_failed_ai_keeps_evidence_and_can_retry(client,monkeypatch):
    raw='arbitrary raw evidence'
    iid=ingest(client,raw)['incident_ids'][0]
    def fail(*a,**k): raise RuntimeError('Internal sensitive exception')
    monkeypatch.setattr(analysis,'analyze',fail)
    answer=client.post('/api/incidents/'+iid+'/analyze')
    assert answer.status_code==502
    assert 'Internal sensitive exception' not in answer.text
    detail=client.get('/api/incidents/'+iid).json()
    assert detail['status']=='failed'
    assert client.get('/api/alerts/'+detail['alerts'][0]['id']+'/raw').json()['raw']==raw
    def succeed(logs,hints,asset,*extra):
        assert logs==[raw]
        return {'title':'Review required','summary':'No behavior established.','severity':'unknown','confidence':'low','mappings':[],'next_steps':['Identify the source.'],'uncertainty':'Insufficient context.','graph_evidence':[]}
    monkeypatch.setattr(analysis,'analyze',succeed)
    assert client.post('/api/incidents/'+iid+'/analyze').json()['status']=='ready'

def test_limits_origin_and_security_headers(client):
    assert client.post('/api/ingest',json={'raw':' '}).status_code==400
    assert client.post('/api/ingest',json={'raw':'{"a":1}\n'*3001,'mode':'batch'}).status_code==400
    assert client.post('/api/ingest',json={'raw':'x'},headers={'Origin':'https://other.example'}).status_code==403
    response=client.get('/')
    assert response.status_code==200
    assert "script-src 'self'" in response.headers['Content-Security-Policy']
    assert response.headers['X-Content-Type-Options']=='nosniff'

def test_real_splunk_samples_and_provenance(client):
    samples=client.get('/api/samples').json()
    assert len(samples)>=2
    sample=client.get('/api/samples/T1059.001').json()
    assert '<Event' in sample['raw'] and sample['events']==1
    original=Path('data/samples/T1059.001.log').read_bytes()
    entry=next(x for x in samples if x['id']=='T1059.001')
    assert hashlib.sha256(original).hexdigest()==entry['sha256']
    assert extract(sample['raw'])['host']=='ar-win-2'

def test_3000_real_events_ingest(client):
    raw=Path('data/samples/T1070.log').read_text(encoding='utf-8')
    logs=split_batch(raw)[:3000]
    assert len(logs)==3000
    batch=''.join(logs)
    started=time.perf_counter()
    result=ingest(client,batch,mode='batch',asset='critical')
    assert result['alert_count']==3000
    with store.connection() as conn:
        assert conn.execute('SELECT count(*) FROM alerts').fetchone()[0]==3000
        assert conn.execute('SELECT raw FROM submissions').fetchone()[0]==batch
    print(f'3000 actual Splunk events: {time.perf_counter()-started:.2f}s, {result["incident_count"]} incidents')

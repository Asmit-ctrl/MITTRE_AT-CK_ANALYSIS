import json
import sqlite3
import time
from pathlib import Path
from tests.test_flow import client, ingest
from app import store, analysis
from app.ingestion import explain_score, extract

def test_endpoint_agent_identity_and_millisecond_timestamp():
    fields=extract('{"aid":"agent-a","UserSid":"sid-a","timestamp":"1658910730575","CommandLine":"powershell.exe"}')
    assert fields['host']=='agent-a' and fields['user']=='sid-a'
    assert fields['epoch']==1658910730.575

def test_ndjson_command_quotes_are_literal(monkeypatch):
    raw='{"CommandLine":"cmd.exe /c vssadmin create shadow /for\\u003dC:"}\n{"CommandLine":"cmd.exe"}'
    responses=iter([analysis.RetrievalPlan(technique_ids=['T1059.003']),analysis.Brief(title='Shell activity',summary='Investigate.',severity='medium',confidence='low',mappings=[analysis.Mapping(technique_id='T1059.003',reason='Command shell',evidence_ref='log1-e1')],uncertainty='Intent unknown.')])
    def ask(system,payload,schema,max_tokens):
        if schema is analysis.Brief: assert payload['literal_evidence']['log1-e1'] in raw and 'vssadmin' in payload['literal_evidence']['log1-e1']
        return next(responses)
    monkeypatch.setattr(analysis,'ask',ask)
    monkeypatch.setattr(analysis,'retrieve',lambda plan:[{'id':'T1059.003'}])
    result=analysis.analyze([raw],[],'high')
    assert result['mappings'] and result['mappings'][0]['evidence_quote'] in raw

def test_resolution_is_distinct_from_triage(client):
    iid=ingest(client,'host=test observed event')['incident_ids'][0]
    payload={'analyst':'Test analyst','note':'Investigation complete','revision':1}
    assert client.post(f'/api/incidents/{iid}/resolve',json=payload).status_code==409
    reviewed=client.post(f'/api/incidents/{iid}/review',json={**payload,'decision':'confirmed'}).json()
    assert client.get('/api/metrics').json()['mean_resolution_seconds'] is None
    resolved=client.post(f'/api/incidents/{iid}/resolve',json={**payload,'revision':reviewed['revision']})
    assert resolved.status_code==200
    assert resolved.json()['first_review']==reviewed['first_review']
    assert resolved.json()['resolved_at']>=reviewed['first_review']
    assert client.post(f'/api/incidents/{iid}/resolve',json={**payload,'revision':resolved.json()['revision']}).status_code==409
    client.put('/api/baseline',json={'minutes':8,'resolution_minutes':30})
    m=client.get('/api/metrics').json()
    assert m['resolved']==1 and m['reviewed']==1
    assert m['resolution_reduction_percent'] is not None
    assert m['mean_resolution_seconds']>=m['mean_triage_seconds']

def test_sample_origin_is_verified_not_client_claimed(client):
    sample=client.get('/api/samples/T1059.001').json()
    info=ingest(client,sample['raw'],sample_id='T1059.001')
    incident=client.get('/api/incidents/'+info['incident_ids'][0]).json()
    source=incident['sources'][0]['source']
    assert source['kind']=='verified_splunk_sample'
    assert source['revision']==sample['source']['revision']
    assert source['dataset_sha256']==sample['source']['sha256']
    assert client.post('/api/ingest',json={'raw':'invented content','sample_id':'T1059.001'}).status_code==400
    assert client.get('/api/integrity').json()['ok']

def test_audit_is_append_only_and_detects_raw_tampering(client):
    info=ingest(client,'evidence unchanged')
    assert client.get('/api/integrity').json()['ok']
    with store.connection() as conn:
        try:
            conn.execute("UPDATE audit SET note='altered'")
        except sqlite3.IntegrityError: pass
        else: raise AssertionError('Audit was editable')
    with store.connection() as conn: conn.execute("UPDATE alerts SET raw='altered'")
    result=client.get('/api/integrity').json()
    assert not result['ok'] and any(x.startswith('alert:') for x in result['problems'])

def test_audit_chain_detects_bypassed_database_guard(client):
    ingest(client,'one event')
    with store.connection() as conn:
        conn.execute('DROP TRIGGER audit_no_update')
        conn.execute("UPDATE audit SET analyst='forged' WHERE id=1")
    assert not client.get('/api/integrity').json()['ok']

def test_mapping_approval_and_versioned_evidence_packet(client,monkeypatch):
    raw='host=a powershell.exe'
    iid=ingest(client,raw)['incident_ids'][0]
    def success(logs,hints,asset,*extra):
        return {'title':'PowerShell observed','summary':'Intent unknown. Review the process.','severity':'medium','confidence':'low','severity_reason':'Shell activity without execution outcome.',
                'mappings':[{'technique_id':'T1059.001','reason':'Shell execution','evidence_quote':'powershell.exe'}],
                'next_steps':['Review process ancestry.'],'uncertainty':'Intent unknown.','graph_evidence':[{'id':'T1059.001','name':'PowerShell','version':'19.2','url':'https://attack.mitre.org/techniques/T1059/001'}],
                'model':'test-model','prompt_version':'test-prompt','stage_seconds':{'planner':0.1,'retrieval':0.01,'brief':0.2}}
    monkeypatch.setattr(analysis,'analyze',success)
    first=client.post(f'/api/incidents/{iid}/analyze').json()
    second=client.post(f'/api/incidents/{iid}/analyze').json()
    assert len(second['analysis_history'])==2
    mapping=second['analysis']['mappings'][0]
    assert mapping['alert_id']==second['alerts'][0]['id'] and mapping['sha256']==second['alerts'][0]['sha256']
    review={'analyst':'Test','note':'Verified original process event','decision':'confirmed','revision':second['revision'],'approved_mappings':['T1003.001']}
    assert client.post(f'/api/incidents/{iid}/review',json=review).status_code==400
    review['approved_mappings']=['T1059.001']
    approved=client.post(f'/api/incidents/{iid}/review',json=review).json()
    assert approved['approved_mappings']==['T1059.001']
    packet=client.get(f'/api/incidents/{iid}/export').json()
    assert len(packet['analysis_runs'])==2
    assert packet['analysis_runs'][0]['snapshot']['prompt_version']=='test-prompt'
    assert packet['audit_records'][-1]['metadata']['approved_mappings']==['T1059.001']
    assert len(packet['audit_records'][-1]['event_hash'])==64
    assert packet['integrity']['ok']
    metrics=client.get('/api/metrics').json()
    assert metrics['analysis_runs']==2 and metrics['analysis_p95_seconds']>=metrics['analysis_p50_seconds']
    with store.connection() as conn: conn.execute("UPDATE analysis_runs SET snapshot='{}' WHERE id=?",(packet['analysis_runs'][0]['id'],))
    assert not client.get('/api/integrity').json()['ok']

def test_critical_asset_risk_is_explainable():
    explanation=explain_score('high','critical',True)
    assert explanation['score']==80
    assert round(explanation['severity_contribution']+explanation['asset_contribution'])==explanation['score']
    assert explanation['alert_count_affects_score'] is False

def test_retrieval_cache_is_bounded_and_expires(monkeypatch):
    monkeypatch.setattr(analysis,'RETRIEVAL_CACHE',{})
    calls=[]
    def retrieve(plan): calls.append(plan); return [{'id':'T1059.001'}]
    monkeypatch.setattr(analysis,'retrieve_uncached',retrieve)
    plan=analysis.RetrievalPlan(technique_ids=['T1059.001'])
    first=analysis.retrieve(plan);first[0]['id']='changed'
    assert analysis.retrieve(plan)==[{'id':'T1059.001'}] and len(calls)==1
    key=(('T1059.001',),())
    analysis.RETRIEVAL_CACHE[key]=(time.monotonic()-301,[{'id':'old'}])
    assert analysis.retrieve(plan)==[{'id':'T1059.001'}] and len(calls)==2

def test_queue_pagination_with_real_batch(client):
    sample=client.get('/api/samples/T1070?count=3000').json()
    start=time.perf_counter()
    info=ingest(client,sample['raw'],mode='batch',sample_id='T1070')
    queue=client.get('/api/queue?page=1').json()
    page2=client.get('/api/queue?page=2').json()
    assert queue['total']==info['incident_count'] and len(queue['items'])==50
    assert not {x['id'] for x in queue['items']} & {x['id'] for x in page2['items']}
    assert client.get('/api/integrity').json()['ok']
    print(f'3000 real events + provenance + 2 queue pages: {time.perf_counter()-start:.2f}s')

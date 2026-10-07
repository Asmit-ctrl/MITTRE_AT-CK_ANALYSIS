import hashlib
import json
from types import SimpleNamespace
from datetime import datetime,timezone
from tests.test_flow import client,ingest
from app import analysis,store

def ts(text):return datetime.fromisoformat(text.replace('Z','+00:00')).timestamp()

def alert(kind,minute=0,host='DB-01',user='alice',src='203.0.113.9',**extra):
    return {'host':host,'user':user,'src_ip':src,'timestamp':f'2026-10-07T10:{minute:02d}:00Z','event_type':kind,**extra}

def iid(client,records):return ingest(client,json.dumps(records),mode='batch',asset='critical')['incident_ids'][0]

def test_auth_to_process_chain_correlates_and_keeps_sources(client):
    records=[alert('auth_failed'),alert('auth_success',2),alert('process',4,CommandLine='cmd.exe /c whoami',Image='cmd.exe'),alert('network_connection',5,dest_ip='198.51.100.4')]
    info=ingest(client,json.dumps(records),mode='batch',asset='critical')
    assert info['incident_count']==1 and info['alert_count']==4
    data=client.get('/api/incidents/'+info['incident_ids'][0]).json()
    assert [x['kind'] for x in data['timeline']]==['auth_failed','auth_success','process','network']
    assert data['risk_explanation']['context_factors'][0]['points']==8
    assert data['observed_users']==['alice'] and data['source_ips']==['203.0.113.9']
    event=data['timeline'][2]
    evidence=client.get('/api/events/'+event['id']+'/evidence').json()
    assert 'whoami' in evidence['raw']
    assert evidence['raw']==evidence['raw_alert'][evidence['start']:evidence['end']]
    assert hashlib.sha256(evidence['raw'].encode()).hexdigest()==evidence['event_sha256']

def test_shared_source_user_preserves_multiple_victims(client):
    incident=iid(client,[alert('auth_failed',host='DB-01'),alert('auth_success',1,host='DB-02')])
    data=client.get('/api/incidents/'+incident).json()
    assert data['affected_hosts']==['DB-01','DB-02']
    assert len(data['timeline'])==2

def test_scan_source_links_victims_without_inventing_user(client):
    records=[alert('scan_detected',host='DB-01',user='unknown'),alert('scan_detected',3,host='DB-02',user='unknown'),alert('scan_detected',20,host='DB-03',user='unknown')]
    result=ingest(client,json.dumps(records),mode='batch')
    assert result['incident_count']==2
    data=client.get('/api/incidents/'+result['incident_ids'][0]).json()
    assert data['affected_hosts']==['DB-01','DB-02'] and data['observed_users']==[]

def test_registered_critical_victim_affects_incident_priority(client):
    client.put('/api/context/asset/DB-02',json={'analyst':'Test','criticality':'critical','owner':'Finance'})
    result=ingest(client,json.dumps([alert('auth_failed',host='DB-01',severity='high'),alert('auth_success',1,host='DB-02',severity='high')]),mode='batch',asset='low')
    data=client.get('/api/incidents/'+result['incident_ids'][0]).json()
    assert data['asset']=='critical' and data['score']==80
    assert client.get('/api/queue').json()['items'][0]['asset']=='critical'

def test_unrelated_entities_and_distant_windows_do_not_merge(client):
    records=[alert('auth_failed'),alert('auth_failed',user='bob',src='198.51.100.2'),{**alert('auth_success'),'timestamp':'2026-10-07T12:00:00Z'}]
    assert ingest(client,json.dumps(records),mode='batch')['incident_count']==3

def test_process_identity_links_connection_without_user(client):
    records=[{'Computer':'DB-01','EventID':'1','ProcessGuid':'guid-1','Image':'powershell.exe','UtcTime':'2026-10-07T10:00:00Z'},
             {'Computer':'db-01','EventID':'3','ProcessGuid':'guid-1','Image':'powershell.exe','SourceIp':'192.0.2.1','DestinationIp':'198.51.100.1','UtcTime':'2026-10-07T10:01:00Z'},
             {'Computer':'DB-01','EventID':'1','ProcessGuid':'different-guid','Image':'powershell.exe','UtcTime':'2026-10-07T10:02:00Z'}]
    result=ingest(client,json.dumps(records),mode='batch')
    assert result['incident_count']==2
    data=client.get('/api/incidents/'+result['incident_ids'][0]).json()
    assert [e['kind'] for e in data['timeline']]==['process','network']

def test_single_ndjson_keeps_original_and_links_internal_events(client):
    raw='  '+json.dumps(alert('auth_failed'))+'\r\n'+json.dumps(alert('auth_success',1))+'\r\n'
    info=ingest(client,raw)
    data=client.get('/api/incidents/'+info['incident_ids'][0]).json()
    assert data['alert_count']==1 and data['event_count']==2
    assert client.get('/api/alerts/'+data['alerts'][0]['id']+'/raw').json()['raw']==raw

def rule(client,**changes):
    payload={'name':'Approved vulnerability scan','entity_kind':'source_ip','entity_value':'203.0.113.9/32','hosts':['DB-01'],'event_types':['scan'],
             'start':ts('2026-10-07T09:50:00Z'),'end':ts('2026-10-07T10:30:00Z'),'approved_by':'Business owner','reason':'Approved maintenance ticket TEST-1'}
    return client.post('/api/business-rules',json={**payload,**changes})

def test_benign_requires_source_host_activity_and_window(client):
    incident=iid(client,[alert('scan_detected')])
    assert rule(client).status_code==200
    data=client.get('/api/incidents/'+incident).json()
    assert data['business_context']['classification']=='likely_benign'
    assert data['score']==25 and data['decision']=='unreviewed' and data['resolved_at'] is None
    outside=iid(client,[{**alert('scan_detected',host='WEB-02'),'timestamp':'2026-10-07T12:00:00Z'}])
    assert client.get('/api/incidents/'+outside).json()['business_context']['classification']=='review_required'
    queue=client.get('/api/queue?filter=all').json()
    assert next(x for x in queue['items'] if x['id']==incident)['business_state']=='likely_benign'

def test_post_scan_credential_evidence_blocks_benign_explanation(client):
    incident=iid(client,[alert('scan_detected')]);rule(client)
    assert client.get('/api/incidents/'+incident).json()['business_context']['classification']=='likely_benign'
    other=alert('process',5,user='other-user',src='198.51.100.8',CommandLine='procdump.exe lsass dump',Image='procdump.exe')
    iid(client,[other])
    data=client.get('/api/incidents/'+incident).json()
    assert data['business_context']['classification']=='review_required'
    assert 'follow-on' in data['business_context']['partial_matches'][0]['reason']
    assert next(x for x in client.get('/api/queue?filter=all').json()['items'] if x['id']==incident)['business_state']=='review_required'

def test_process_exception_needs_exact_command(client):
    assert rule(client,event_types=['process']).status_code==400
    incident=iid(client,[alert('process',CommandLine='powershell.exe -encodedcommand evil',Image='powershell.exe')])
    assert rule(client,event_types=['process'],command_exact='powershell.exe approved.ps1').status_code==200
    assert client.get('/api/incidents/'+incident).json()['business_context']['classification']=='review_required'

def test_context_is_audited_and_reputation_not_invented(client):
    incident=iid(client,[alert('auth_failed')])
    assert client.put('/api/context/asset/DB-01',json={'analyst':'Test','owner':'Finance','os':'Windows','environment':'Production','criticality':'critical','internet_facing':False}).status_code==200
    assert client.put('/api/context/user/alice',json={'analyst':'Test','role':'Database admin','privileged':True}).status_code==200
    assert client.put('/api/context/ip/203.0.113.9',json={'analyst':'Test','reputation':'malicious'}).status_code==400
    data=client.get('/api/incidents/'+incident).json()
    assert data['asset_context'][0]['owner']=='Finance'
    assert data['user_context'][0]['privileged'] is True
    assert data['ip_context'][0]['reputation']=='unknown'
    assert data['ip_context'][0]['incidents']==1
    assert client.get('/api/integrity').json()['ok']

def test_disposition_notes_assignment_checklist_and_handoff(client):
    incident=iid(client,[alert('auth_failed')]);data=client.get('/api/incidents/'+incident).json()
    assert client.post(f'/api/incidents/{incident}/notes',json={'analyst':'Test','note':'Owner contacted; verification pending.'}).status_code==200
    assert client.post(f'/api/incidents/{incident}/assign',json={'analyst':'Test','note':'Needs Tier-2 review','assignee':'Tier-2'}).status_code==200
    item=data['playbook'][0]['item']
    assert client.put(f'/api/incidents/{incident}/checklist',json={'analyst':'Test','item':item,'done':True}).status_code==200
    data=client.get('/api/incidents/'+incident).json()
    result=client.post(f'/api/incidents/{incident}/review',json={'analyst':'Test','note':'Authentication attempts observed; compromise unconfirmed','revision':data['revision'],'decision':'attack_attempt'})
    assert result.json()['disposition']=='attack_attempt' and result.json()['resolved_at'] is None
    assert result.json()['playbook'][0]['done']
    assert 'Owner contacted' in client.get('/api/handoff').text
    assert 'attack_attempt' in client.get('/api/handoff').text

def test_response_requests_require_observed_targets_and_other_approver(client):
    incident=iid(client,[alert('auth_failed')])
    payload={'analyst':'Tier-1','note':'Suspicious activity requires containment review','kind':'block_ip','target':'203.0.113.9'}
    request=client.post(f'/api/incidents/{incident}/response-requests',json=payload)
    assert request.status_code==200 and request.json()['executed'] is False
    request_id=request.json()['id']
    assert client.post('/api/response-requests/'+request_id+'/approve',json={'analyst':'Tier-1','note':'Self approval'}).status_code==409
    approved=client.post('/api/response-requests/'+request_id+'/approve',json={'analyst':'Tier-2','note':'Approved pending external enforcement'})
    assert approved.json()['status']=='approved_not_executed' and approved.json()['executed'] is False
    assert client.post(f'/api/incidents/{incident}/response-requests',json={**payload,'target':'192.0.2.99'}).status_code==400
    assert client.get('/api/integrity').json()['ok']

def test_ai_claims_require_literal_references(monkeypatch):
    raw='host=DB-01 user=alice powershell.exe'
    plan=analysis.RetrievalPlan(technique_ids=['T1059.001'])
    brief=analysis.Brief(title='Shell observed',summary='Should not be blindly displayed.',severity='low',confidence='medium',uncertainty='Intent unknown.',claims=[
        analysis.EvidenceClaim(text='PowerShell appears in the event.',status='observed',evidence_refs=['log1-e1']),
        analysis.EvidenceClaim(text='Invented compromise.',status='suspected',evidence_refs=['nonexistent'])])
    results=iter([plan,brief]);monkeypatch.setattr(analysis,'ask',lambda *args,**kwargs:next(results));monkeypatch.setattr(analysis,'retrieve',lambda plan:[])
    result=analysis.analyze([raw],[],'critical',{'business_context':{'classification':'review_required'}})
    assert len(result['claims'])==1
    assert result['summary']=='PowerShell appears in the event.' and 'Invented' not in result['summary']

def test_provider_is_requested_to_enforce_json_output(monkeypatch):
    captured={}
    def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content='{"technique_ids":[],"search_terms":[]}'))])
    monkeypatch.setattr(analysis,'client',lambda:SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    result=analysis.ask('Return a retrieval plan.',{'raw_logs':['unchanged']},analysis.RetrievalPlan,600)
    assert result.technique_ids==[]
    assert captured['response_format']=={'type':'json_object'}

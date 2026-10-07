import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
from . import store, analysis
from .ingestion import score, validate_input
from .provenance import source_for, digest
from . import investigation, workbench

@asynccontextmanager
async def lifespan(app):
    store.initialize()
    workbench.initialize()
    for scope in ['demo','lab']:
        token=store.WORKSPACE.set(scope)
        try:store.initialize();workbench.initialize()
        finally:store.WORKSPACE.reset(token)
    workbench.start_workers()
    yield
    workbench.STOP.set()
    if analysis.graph.cache_info().currsize: analysis.graph().close()

app = FastAPI(title='Shiftline', lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost','127.0.0.1','testserver'])
app.mount('/static',StaticFiles(directory=ROOT / 'static'),name='static')
app.include_router(workbench.router)

@app.middleware('http')
async def guard(request: Request, call_next):
    if request.method in {'POST','PATCH','PUT','DELETE'}:
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail':'Cross-origin requests are disabled.'},status_code=403)
        if int(request.headers.get('content-length','0')) > 12_000_000:
            return JSONResponse({'detail':'Submission exceeds the 8 MB input limit.'},status_code=413)
    scope=request.headers.get('x-workspace') or request.query_params.get('scope','live')
    if scope not in {'live','demo','lab'}:return JSONResponse({'detail':'Unknown workspace.'},status_code=400)
    token=store.WORKSPACE.set(scope)
    try:response = await call_next(request)
    finally:store.WORKSPACE.reset(token)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response

class IngestRequest(BaseModel):
    raw: str = Field(max_length=8_000_000)
    mode: Literal['single','batch'] = 'single'
    asset: Literal['low','standard','high','critical'] = 'standard'
    host: str = Field(default='',max_length=160)
    sample_id: str | None = Field(default=None,max_length=20)

class ReviewRequest(BaseModel):
    decision: Literal['confirmed','false_positive','escalated','true_attack','attack_attempt','benign_trigger','unknown']
    analyst: str = Field(min_length=1,max_length=80)
    note: str = Field(min_length=1,max_length=1200)
    revision: int
    approved_mappings: list[str] = Field(default_factory=list,max_length=6)
    disposition: Literal['true_attack','attack_attempt','benign_trigger','false_positive','unknown'] = 'unknown'

class ResolutionRequest(BaseModel):
    analyst: str = Field(min_length=1,max_length=80)
    note: str = Field(min_length=1,max_length=1200)
    revision: int

class AssetRequest(BaseModel):
    asset: Literal['low','standard','high','critical']
    revision: int

class BaselineRequest(BaseModel):
    minutes: float = Field(gt=0,le=1440)
    resolution_minutes: float | None = Field(default=None,gt=0,le=10080)

class AnalystInput(BaseModel):
    analyst: str = Field(min_length=1,max_length=80)
    note: str = Field(min_length=1,max_length=1200)

class ContextInput(BaseModel):
    analyst: str = Field(min_length=1,max_length=80)
    owner: str = Field(default='',max_length=160)
    os: str = Field(default='',max_length=80)
    environment: str = Field(default='',max_length=80)
    criticality: Literal['low','standard','high','critical'] | None = None
    internet_facing: bool | None = None
    vulnerabilities: str = Field(default='',max_length=1000)
    exceptions: str = Field(default='',max_length=1000)
    role: str = Field(default='',max_length=160)
    privileged: bool | None = None
    reputation: Literal['unknown','benign','suspicious','malicious'] = 'unknown'
    reason: str = Field(default='',max_length=1000)

class RuleInput(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    entity_kind: Literal['source_ip','user','process']
    entity_value: str = Field(min_length=1,max_length=200)
    hosts: list[str] = Field(min_length=1,max_length=30)
    event_types: list[Literal['scan','auth_failed','auth_success','process','network','file']] = Field(min_length=1,max_length=6)
    start: float
    end: float
    approved_by: str = Field(min_length=1,max_length=80)
    reason: str = Field(min_length=1,max_length=1000)
    command_exact: str = Field(default='',max_length=2000)

class AssignmentInput(AnalystInput):
    assignee: str = Field(min_length=1,max_length=80)

class ChecklistInput(BaseModel):
    analyst: str = Field(min_length=1,max_length=80)
    item: str = Field(min_length=1,max_length=160)
    done: bool

class ResponseInput(AnalystInput):
    kind: Literal['contain_host','block_ip','disable_account']
    target: str = Field(min_length=1,max_length=200)

@app.get('/')
def home(): return FileResponse(ROOT / 'static' / 'index.html')

@app.get('/incident')
def incident_page():return FileResponse(ROOT / 'static' / 'incident.html')

@app.get('/lab')
def lab_page():return FileResponse(ROOT / 'static' / 'lab.html')

@app.get('/api/health')
def health(): return {'ok':True,'mode':'local-prototype','model':'nvidia/nemotron-3.5-lightning-30b-a3b'}

@app.get('/api/connections')
def connections():
    try:
        analysis.graph().verify_connectivity()
        graph_status = 'connected'
    except Exception:
        graph_status = 'unavailable'
    import os
    return {'neo4j':graph_status,'nvidia':'configured' if os.getenv('NVIDIA_API_KEY') else 'missing'}

@app.post('/api/ingest')
def ingest(data: IngestRequest):
    try:
        logs = validate_input(data.raw,data.mode)
        source=source_for(data.raw,data.sample_id)
    except ValueError as exc: raise HTTPException(400,str(exc)) from exc
    return store.ingest(data.raw,logs,data.mode,data.asset,data.host,source)

@app.get('/api/incidents')
def incidents(): return store.list_incidents()

@app.get('/api/queue')
def queue(filter: Literal['pending','reviewed','all','open','escalated']='open',page: int=1):
    if page<1: raise HTTPException(400,'Page must be positive.')
    metrics=store.metrics()
    total=metrics['pending'] if filter=='pending' else metrics['incidents']-metrics['pending'] if filter=='reviewed' else metrics['open_incidents'] if filter=='open' else metrics['escalations'] if filter=='escalated' else metrics['incidents']
    return {'items':store.list_incidents(filter,50,(page-1)*50),'total':total,'page':page,'page_size':50}

@app.get('/api/incidents/{incident_id}')
def detail(incident_id: str):
    item = store.detail(incident_id)
    if item is None: raise HTTPException(404,'Incident not found.')
    return investigation.enrich(item)

@app.get('/api/events/{event_id}/evidence')
def event_evidence(event_id: str):
    with store.connection() as conn:
        row=conn.execute('SELECT e.data,e.alert_id,e.incident_id,a.raw,a.sha256 FROM observed_events e JOIN alerts a ON a.id=e.alert_id WHERE e.id=?',(event_id,)).fetchone()
    if not row:raise HTTPException(404,'Event not found.')
    event=json.loads(row['data'])
    return {'event_id':event_id,'alert_id':row['alert_id'],'incident_id':row['incident_id'],'raw':row['raw'][event['start']:event['end']],
            'raw_alert':row['raw'],'alert_sha256':row['sha256'],'event_sha256':event['event_sha256'],'start':event['start'],'end':event['end']}

@app.put('/api/context/{kind}/{entity}')
def save_context(kind: Literal['asset','user','ip'],entity: str,data: ContextInput):
    if not entity.strip() or entity=='unknown' or not data.analyst.strip():raise HTTPException(400,'Use a known entity and analyst name.')
    if kind=='ip' and data.reputation!='unknown' and not data.reason.strip():raise HTTPException(400,'Add the source or reason for this reputation assessment.')
    allowed={'asset':['owner','os','environment','criticality','internet_facing','vulnerabilities','exceptions'],
             'user':['role','privileged','owner','exceptions'],'ip':['reputation','owner','reason']}
    values={key:getattr(data,key) for key in allowed[kind]};values['recorded_by']=data.analyst
    with store.connection() as conn:
        conn.execute('INSERT OR REPLACE INTO context_records VALUES (?,?,?,?)',(kind,entity.lower(),json.dumps(values),time.time()))
        store.append_audit(conn,None,'context_updated',data.analyst,'Business context recorded.',{'kind':kind,'entity':entity,'values':values})
        if kind=='asset' and data.criticality:
            conn.execute('UPDATE incidents SET asset=?,revision=revision+1 WHERE lower(host)=?',(data.criticality,entity.lower()))
        for row in conn.execute('SELECT id FROM incidents').fetchall():investigation.refresh_risk(conn,row['id'])
    return {'saved':True,'source':'Analyst-entered business context'}

@app.get('/api/business-rules')
def business_rules():
    with store.connection() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM benign_rules ORDER BY created DESC')]

@app.post('/api/business-rules')
def create_rule(data: RuleInput):
    if data.end<=data.start or not data.approved_by.strip() or not data.reason.strip():raise HTTPException(400,'Use a valid window, approver and business justification.')
    if 'process' in data.event_types and not data.command_exact.strip():raise HTTPException(400,'A process exception requires an explicitly approved exact command.')
    if data.entity_kind=='source_ip':
        import ipaddress
        try:ipaddress.ip_network(data.entity_value,strict=False)
        except ValueError as exc:raise HTTPException(400,'Enter an IP or CIDR.') from exc
    rule_id=store.uid()
    with store.connection() as conn:
        conn.execute('INSERT INTO benign_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',(rule_id,data.name,data.entity_kind,data.entity_value,
            json.dumps([x.lower() for x in data.hosts]),json.dumps(data.event_types),data.start,data.end,data.approved_by,data.reason,time.time(),data.command_exact))
        store.append_audit(conn,None,'business_exception_approved',data.approved_by,data.reason,{'rule_id':rule_id,**data.model_dump()})
        for row in conn.execute('SELECT id FROM incidents').fetchall():investigation.refresh_risk(conn,row['id'])
    return {'id':rule_id,'status':'active_within_explicit_scope','auto_close':False}

@app.post('/api/incidents/{incident_id}/notes')
def add_note(incident_id: str,data: AnalystInput):
    detail(incident_id)
    if not data.analyst.strip() or not data.note.strip():raise HTTPException(400,'Add your name and note.')
    with store.connection() as conn:
        conn.execute('INSERT INTO investigation_notes VALUES (?,?,?,?,?)',(store.uid(),incident_id,data.analyst,data.note,time.time()))
        store.append_audit(conn,incident_id,'note_added',data.analyst,data.note)
    return detail(incident_id)

@app.post('/api/incidents/{incident_id}/assign')
def assign(incident_id: str,data: AssignmentInput):
    detail(incident_id)
    if not data.analyst.strip() or not data.assignee.strip() or not data.note.strip():raise HTTPException(400,'Add analyst, assignee and assignment reason.')
    with store.connection() as conn:
        conn.execute('UPDATE incidents SET assigned_to=?,revision=revision+1 WHERE id=?',(data.assignee,incident_id))
        store.append_audit(conn,incident_id,'assigned',data.analyst,data.note,{'assignee':data.assignee})
    return detail(incident_id)

@app.put('/api/incidents/{incident_id}/checklist')
def checklist(incident_id: str,data: ChecklistInput):
    item=detail(incident_id)
    if not data.analyst.strip() or data.item not in {x['item'] for x in item['playbook']}:raise HTTPException(400,'Use an item from this incident playbook and your analyst name.')
    with store.connection() as conn:
        conn.execute('INSERT OR REPLACE INTO checklist_items VALUES (?,?,?,?,?)',(incident_id,data.item,data.done,data.analyst,time.time()))
        store.append_audit(conn,incident_id,'checklist_updated',data.analyst,data.item,{'done':data.done})
    return detail(incident_id)

@app.post('/api/incidents/{incident_id}/response-requests')
def request_response(incident_id: str,data: ResponseInput):
    info=detail(incident_id)
    targets={'contain_host':info['affected_hosts'],'block_ip':info['source_ips'],'disable_account':info['observed_users']}
    if data.target not in targets[data.kind] or data.target=='unknown':raise HTTPException(400,'Select an observed target from this incident.')
    if not data.analyst.strip() or not data.note.strip():raise HTTPException(400,'Add requester and justification.')
    request_id=store.uid()
    with store.connection() as conn:
        conn.execute('INSERT INTO response_requests VALUES (?,?,?,?,?,?,?,?,?)',(request_id,incident_id,data.kind,data.target,data.analyst,data.note,'pending_approval',None,time.time()))
        store.append_audit(conn,incident_id,'response_requested',data.analyst,data.note,{'request_id':request_id,'kind':data.kind,'target':data.target,'execution':'not_executed'})
    return {'id':request_id,'status':'pending_approval','executed':False,'message':'No EDR/firewall/identity executor is connected.'}

@app.post('/api/response-requests/{request_id}/approve')
def approve_response(request_id: str,data: AnalystInput):
    with store.connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute('SELECT * FROM response_requests WHERE id=?',(request_id,)).fetchone()
        if not row:raise HTTPException(404,'Request not found.')
        if row['status']!='pending_approval' or row['requested_by'].strip().lower()==data.analyst.strip().lower():raise HTTPException(409,'A different named approver is required; request must be pending.')
        if not data.analyst.strip() or not data.note.strip():raise HTTPException(400,'Add approver name and reason.')
        conn.execute("UPDATE response_requests SET status='approved_not_executed',approved_by=? WHERE id=?",(data.analyst,request_id))
        store.append_audit(conn,row['incident_id'],'response_approved',data.analyst,data.note,{'request_id':request_id,'execution':'not_executed'})
    return {'status':'approved_not_executed','executed':False,'message':'Approval recorded; external execution remains required. Names are self-declared in this local prototype.'}

@app.get('/api/alerts/{alert_id}/raw')
def raw_alert(alert_id: str):
    with store.connection() as conn:
        row = conn.execute('SELECT raw,sha256 FROM alerts WHERE id=?',(alert_id,)).fetchone()
    if not row: raise HTTPException(404,'Alert not found.')
    return dict(row)

@app.get('/api/submissions/{submission_id}/raw')
def raw_submission(submission_id: str):
    with store.connection() as conn:
        row = conn.execute('SELECT raw FROM submissions WHERE id=?',(submission_id,)).fetchone()
    if not row: raise HTTPException(404,'Submission not found.')
    return Response(row['raw'],media_type='text/plain; charset=utf-8')

@app.post('/api/incidents/{incident_id}/analyze')
def analyze(incident_id: str):
    if not analysis.AI_GATE.acquire(blocking=False): raise HTTPException(429,'Two analyses are already running. Try again shortly.')
    try:
        with store.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
            if not row: raise HTTPException(404,'Incident not found.')
            if row['status']=='analyzing': raise HTTPException(409,'Analysis is already running.')
            if row['decision']!='unreviewed': raise HTTPException(409,'This incident has already been reviewed.')
            conn.execute("UPDATE incidents SET status='analyzing',revision=revision+1 WHERE id=?",(incident_id,))
            # Analyze up to three distinct actual events, preserving each in full.
            rows = conn.execute('SELECT id,raw,sha256,extracted FROM alerts WHERE incident_id=? GROUP BY sha256 ORDER BY created,id LIMIT 3',(incident_id,)).fetchall()
            total = conn.execute('SELECT count(*) FROM alerts WHERE incident_id=?',(incident_id,)).fetchone()[0]
        raw_logs, hints, selected_alerts = [], [], []
        for alert in rows:
            if raw_logs and sum(map(len,raw_logs))+len(alert['raw'])>120_000: break
            raw_logs.append(alert['raw'])
            selected_alerts.append({'alert_id':alert['id'],'sha256':alert['sha256']})
            hints.extend(json.loads(alert['extracted'])['hints'])
        started = time.perf_counter()
        try:
            result = analysis.analyze(raw_logs,list(dict.fromkeys(hints))[:6],row['asset'],investigation.model_context(incident_id))
            result['total_alerts'] = total
            result['coverage_note'] = f"Analyzed {len(raw_logs)} distinct representative log(s) from {total} alert(s). All originals are retained."
            result['input_evidence']=selected_alerts
            for mapping in result['mappings']:
                match=next((index for index,raw in enumerate(raw_logs) if mapping['evidence_quote'] in raw),None)
                if match is not None: mapping.update(selected_alerts[match])
            with store.connection() as conn:
                for claim in result.get('claims',[]):
                    for evidence in claim['evidence']:
                        match=next((index for index,raw in enumerate(raw_logs) if evidence['quote'] in raw),None)
                        if match is None:continue
                        evidence.update(selected_alerts[match]);position=raw_logs[match].find(evidence['quote'])
                        for event in conn.execute('SELECT id,data FROM observed_events WHERE alert_id=?',(evidence['alert_id'],)):
                            data=json.loads(event['data'])
                            if data['start']<=position<data['end']:evidence['event_id']=event['id'];break
            run_id=store.uid()
            snapshot=json.dumps(result,sort_keys=True,ensure_ascii=False)
            duration=time.perf_counter()-started
            with store.connection() as conn:
                conn.execute('INSERT INTO analysis_runs VALUES (?,?,?,?,?,?)',(run_id,incident_id,time.time(),duration,'success',snapshot))
                conn.execute('''UPDATE incidents SET title=?,severity=?,score=?,status='ready',analysis=?,analysis_seconds=?,updated=?,revision=revision+1 WHERE id=?''',
                             (result['title'],result['severity'],score(result['severity'],row['asset']),json.dumps(result),time.perf_counter()-started,time.time(),incident_id))
                investigation.refresh_risk(conn,incident_id)
                store.append_audit(conn,incident_id,'analysis','system',result['coverage_note'],{'run_id':run_id,'snapshot_sha256':digest(snapshot),'model':result.get('model'),'prompt_version':result.get('prompt_version'),'input_evidence':selected_alerts})
        except Exception as exc:
            with store.connection() as conn:
                conn.execute("UPDATE incidents SET status='failed' WHERE id=?",(incident_id,))
                run_id=store.uid();snapshot=json.dumps({'error_type':type(exc).__name__,'input_evidence':selected_alerts})
                conn.execute('INSERT INTO analysis_runs VALUES (?,?,?,?,?,?)',(run_id,incident_id,time.time(),time.perf_counter()-started,'failed',snapshot))
                store.append_audit(conn,incident_id,'analysis_failed','system','Analysis failed; evidence retained.',{'run_id':run_id,'snapshot_sha256':digest(snapshot),'error_type':type(exc).__name__})
            logging.getLogger('shiftline').warning('Analysis failed (%s), incident %s',type(exc).__name__,incident_id)
            raise HTTPException(502,'Analysis could not complete. Check NVIDIA/Neo4j connectivity and retry. Your original logs are saved.') from exc
        return detail(incident_id)
    finally: analysis.AI_GATE.release()

@app.patch('/api/incidents/{incident_id}/asset')
def asset(incident_id: str, data: AssetRequest):
    with store.connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row: raise HTTPException(404,'Incident not found.')
        if row['revision']!=data.revision or row['status']=='analyzing': raise HTTPException(409,'Incident changed. Refresh before updating.')
        conn.execute('UPDATE incidents SET asset=?,score=?,revision=revision+1,updated=? WHERE id=?',(data.asset,score(row['severity'],data.asset),time.time(),incident_id))
        investigation.refresh_risk(conn,incident_id)
        store.append_audit(conn,incident_id,'asset_changed','analyst',f"{row['asset']} → {data.asset}",{'previous_score':row['score'],'new_score':score(row['severity'],data.asset)})
    return detail(incident_id)

@app.post('/api/incidents/{incident_id}/review')
def review(incident_id: str, data: ReviewRequest):
    if not data.note.strip() or not data.analyst.strip(): raise HTTPException(400,'Add your name and decision reason.')
    with store.connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row: raise HTTPException(404,'Incident not found.')
        if row['status']=='analyzing' or row['revision']!=data.revision: raise HTTPException(409,'Incident changed. Refresh before reviewing.')
        if row['resolved_at'] is not None: raise HTTPException(409,'This incident is resolved. Its final review is preserved.')
        candidates={m['technique_id'] for m in json.loads(row['analysis'] or '{}').get('mappings',[])}
        approved=list(dict.fromkeys(data.approved_mappings))
        if not set(approved)<=candidates: raise HTTPException(400,'Approve only evidence-backed candidate mappings.')
        disposition=data.disposition if data.decision=='escalated' else 'true_attack' if data.decision=='confirmed' else data.decision
        if disposition in {'false_positive','benign_trigger'} and approved:raise HTTPException(400,'A benign/false-positive decision cannot approve attack mappings.')
        conn.execute('''UPDATE incidents SET decision=?,disposition=?,approved_mappings=?,first_review=coalesce(first_review,?),updated=?,revision=revision+1 WHERE id=?''',(data.decision,disposition,json.dumps(approved),time.time(),time.time(),incident_id))
        if data.decision=='escalated':conn.execute("UPDATE incidents SET assigned_to='Tier-2' WHERE id=?",(incident_id,))
        store.append_audit(conn,incident_id,data.decision,data.analyst.strip(),data.note.strip(),{'disposition':disposition,'approved_mappings':approved,'revision_reviewed':data.revision})
    return detail(incident_id)

@app.post('/api/incidents/{incident_id}/resolve')
def resolve(incident_id: str,data: ResolutionRequest):
    if not data.analyst.strip() or not data.note.strip(): raise HTTPException(400,'Add your name and resolution reason.')
    with store.connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row: raise HTTPException(404,'Incident not found.')
        if row['revision']!=data.revision or row['decision']=='unreviewed' or row['resolved_at'] is not None: raise HTTPException(409,'Review first, refresh the incident, or check whether it is already resolved.')
        now=time.time()
        conn.execute('UPDATE incidents SET resolved_at=?,updated=?,revision=revision+1 WHERE id=?',(now,now,incident_id))
        store.append_audit(conn,incident_id,'resolved',data.analyst.strip(),data.note.strip(),{'resolution_seconds':now-row['created']})
    return detail(incident_id)

@app.get('/api/incidents/{incident_id}/export')
def evidence_export(incident_id: str):
    data=detail(incident_id)
    with store.connection() as conn:
        data['analysis_runs']=[dict(r) for r in conn.execute('SELECT * FROM analysis_runs WHERE incident_id=? ORDER BY created',(incident_id,))]
        for run in data['analysis_runs']: run['snapshot']=json.loads(run['snapshot'])
        data['audit_records']=[dict(r) for r in conn.execute('SELECT * FROM audit WHERE incident_id=? ORDER BY id',(incident_id,))]
        for event in data['audit_records']: event['metadata']=json.loads(event['metadata'])
    data['integrity']=store.verify_integrity()
    return JSONResponse(data,headers={'Content-Disposition':f'attachment; filename="incident-{incident_id[:8]}-evidence.json"'})

@app.get('/api/integrity')
def integrity(): return store.verify_integrity()

@app.get('/api/metrics')
def metrics(): return store.metrics()

@app.put('/api/baseline')
def baseline(data: BaselineRequest):
    with store.connection() as conn:
        conn.execute("INSERT OR REPLACE INTO settings VALUES ('baseline_seconds',?)",(str(data.minutes*60),))
        if data.resolution_minutes is not None: conn.execute("INSERT OR REPLACE INTO settings VALUES ('resolution_baseline_seconds',?)",(str(data.resolution_minutes*60),))
        elif 'resolution_minutes' in data.model_fields_set: conn.execute("DELETE FROM settings WHERE key='resolution_baseline_seconds'")
        store.append_audit(conn,None,'baseline_changed','analyst','Measured manual baseline saved.',data.model_dump())
    return store.metrics()

@app.get('/api/samples')
def samples():
    path = ROOT / 'data' / 'samples' / 'manifest.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else []

@app.get('/api/samples/{sample_id}')
def sample(sample_id: str, count: int = 1):
    if count not in {1,20,100,3000}: raise HTTPException(400,'Choose 1, 20, 100, or 3000 events.')
    manifest = next((x for x in samples() if x['id']==sample_id),None)
    if not manifest: raise HTTPException(404,'Sample not found.')
    raw = (ROOT / 'data' / 'samples' / manifest['filename']).read_text(encoding='utf-8')
    from .ingestion import split_batch
    logs = split_batch(raw)[:count]
    return {'raw':''.join(logs),'events':len(logs),'source':manifest}

@app.get('/api/handoff')
def handoff():
    cutoff=time.time()-12*3600
    items = [x for x in store.list_incidents() if x['resolved_at'] is None or x['updated']>=cutoff]
    blocks = ['# Shiftline · Shift handoff','',f'Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime())}',
              'Includes every unresolved incident and closures updated during the last 12 hours. All times below are from recorded evidence/history.','']
    for item in items:
        info = detail(item['id'])
        brief = info['analysis']
        blocks += [f"## {item['title']}",f"Asset: {item['host']} | Criticality: {item['asset']} | Risk: {item['score']}/100 | Alerts: {item['alert_count']} | Decision: {item['decision']}",
                   brief['summary'] if brief else 'AI analysis pending. Analyst review required.']
        blocks += ['Disposition: '+info['disposition'],'Assigned: '+(info['assigned_to'] or 'Unassigned'),'Business assessment: '+info['business_context']['classification']]
        if brief:
            blocks += ['Candidate ATT&CK: ' + ', '.join(m['technique_id'] for m in brief['mappings']), brief['coverage_note'], 'Uncertainty: ' + brief['uncertainty']]
            blocks += ['Analyst-approved ATT&CK: '+(', '.join(info['approved_mappings']) or 'None'),'Resolution: '+('Resolved' if info['resolved_at'] else 'Open')]
            blocks += ['- ' + step for step in brief['next_steps']]
        if info['audit']:
            review_actions = [x for x in info['audit'] if x['action'] in {'confirmed','false_positive','escalated','true_attack','attack_attempt','benign_trigger','unknown'}]
            if review_actions: blocks += [f"Analyst: {review_actions[0]['analyst']} · {review_actions[0]['note']}"]
        blocks += ['Recent note: '+n['analyst']+' · '+n['note'] for n in info['notes'][:3]]
        blocks += ['Response: '+r['kind']+' · '+r['target']+' · '+r['status']+' (not executed)' for r in info['response_requests']]
        blocks += ['']
    return Response('\n'.join(blocks), media_type='text/markdown', headers={'Content-Disposition':'attachment; filename="shift-handoff.md"'})

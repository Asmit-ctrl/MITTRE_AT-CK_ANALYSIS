"""Tier-1 context derived from retained evidence, plus explicitly entered business facts."""
import ipaddress
import json
import time
from collections import Counter
from .ingestion import explain_score,score,ASSET_WEIGHTS

def events_for(conn,incident_id):
    rows=conn.execute('SELECT * FROM observed_events WHERE incident_id=? ORDER BY epoch IS NULL,epoch,id',(incident_id,)).fetchall()
    return [{**json.loads(r['data']),'id':r['id'],'alert_id':r['alert_id']} for r in rows]

def context(conn,kind,entity):
    row=conn.execute('SELECT data,updated FROM context_records WHERE kind=? AND entity=?',(kind,entity.lower())).fetchone()
    return {**json.loads(row['data']),'updated':row['updated'],'source':'Analyst-entered business context'} if row else {}

def entity_matches(kind,value,event):
    if kind=='source_ip':
        try:return ipaddress.ip_address(event['src_ip']) in ipaddress.ip_network(value,strict=False)
        except ValueError:return False
    if kind=='user':return event['user'].lower()==value.lower()
    if kind=='process':return event['image'].lower()==value.lower()
    return False

def benign_assessment(conn,events):
    rules=conn.execute('SELECT * FROM benign_rules ORDER BY created DESC').fetchall()
    partial=[]
    dangerous={'credential_access','log_clear'}
    for rule in rules:
        hosts=json.loads(rule['hosts']);kinds=json.loads(rule['event_types'])
        matches=[e for e in events if entity_matches(rule['entity_kind'],rule['entity_value'],e)]
        if not matches:continue
        reasons=[]
        for e in events:
            if not entity_matches(rule['entity_kind'],rule['entity_value'],e):reasons.append('Other source/account/process activity is outside this exception.')
            if e['host']=='unknown' or ('*' not in hosts and e['host'].lower() not in hosts):reasons.append('Target host does not match the approved scope.')
            if e['epoch'] is None or not rule['start']<=e['epoch']<=rule['end']:reasons.append('Event time is unknown or outside the approved window.')
            if e['kind'] not in kinds or e['kind'] in dangerous:reasons.append('Observed activity is outside the approved activity types.')
            if e['kind']=='process' and (not rule['command_exact'] or e['command']!=rule['command_exact']):reasons.append('Process command does not match an explicitly approved exact command.')
        timed=[e for e in matches if e['epoch'] is not None]
        for host in {e['host'] for e in matches if e['host']!='unknown'}:
            if timed:
                follow=conn.execute("SELECT id FROM observed_events WHERE host=? AND epoch>=? AND epoch<=? AND kind IN ('credential_access','log_clear') LIMIT 1",
                                     (host,min(e['epoch'] for e in timed),max(e['epoch'] for e in timed)+3600)).fetchone()
                if follow:reasons.append('Credential-access or log-clearing evidence exists on this target in the follow-on hour.')
        if not reasons and events:
            return {'classification':'likely_benign','confidence':'Policy match; not a calibrated probability','rule_id':rule['id'],
                    'rule_name':rule['name'],'approved_by':rule['approved_by'],'reason':rule['reason'],
                    'facts':['Exact source/account/process scope matched.','Affected host and event type matched.','Every observed event falls inside the approved window.'],
                    'caveat':'No out-of-scope follow-on event in this incident. Uningested telemetry is unknown; analyst review is still required.'}
        partial.append({'rule_name':rule['name'],'reason':' '.join(dict.fromkeys(reasons))})
    return {'classification':'review_required','confidence':'No fully matching approved exception','partial_matches':partial[:3],
            'reason':'Business justification has not been established. Missing context is not evidence of malicious intent.'}

def assess_risk(conn,row,events):
    known=[context(conn,'asset',host).get('criticality') for host in {e['host'] for e in events if e['host']!='unknown'}]
    effective=max([row['asset']]+[x for x in known if x in ASSET_WEIGHTS],key=ASSET_WEIGHTS.get)
    base=explain_score(row['severity'],effective,bool(row['analysis']))
    if 'ai_classification' in row.keys() and row['ai_classification'] and not row['analysis']:
        classification=json.loads(row['ai_classification'])
        base['severity_source']='NVIDIA NIM evidence classification; analyst review required'
        base['severity_reason']=classification['reason']
    factors=[];kinds={e['kind'] for e in events}
    ordered=[e['kind'] for e in events if e['epoch'] is not None]
    auth_chain=False
    if 'auth_failed' in ordered and 'auth_success' in ordered:
        failure=ordered.index('auth_failed');success=next((i for i,k in enumerate(ordered) if k=='auth_success' and i>failure),None)
        auth_chain=success is not None and any(k in {'process','network','credential_access'} for k in ordered[success+1:])
    if auth_chain:factors.append({'points':8,'reason':'Failed authentication → success → process/network activity in the observed sequence.'})
    for user in {e['user'] for e in events if e['user']!='unknown'}:
        if context(conn,'user',user).get('privileged') is True and 'credential_access' in kinds:
            factors.append({'points':5,'reason':'Observed credential-access activity involves an explicitly registered privileged account.'});break
    for ip in {e['src_ip'] for e in events if e['src_ip']}:
        if context(conn,'ip',ip).get('reputation')=='malicious':
            factors.append({'points':10,'reason':'Source is marked malicious in analyst-entered reputation context.'});break
    benign=benign_assessment(conn,events)
    total=min(100,base['score']+sum(f['points'] for f in factors))
    if benign['classification']=='likely_benign' and total>25:
        factors.append({'points':25-total,'reason':'All observed activity matches the approved business exception; review still required.'});total=25
    band='Critical' if total>=80 else 'High' if total>=60 else 'Medium' if total>=40 else 'Low'
    return {**base,'base_score':base['score'],'score':total,'band':band,'context_factors':factors},benign

def refresh_risk(conn,incident_id):
    row=conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
    if not row:return
    explanation,benign=assess_risk(conn,row,events_for(conn,incident_id))
    conn.execute('UPDATE incidents SET score=?,business_state=? WHERE id=?',(explanation['score'],benign['classification'],incident_id))

PLAYBOOKS={
 'generic':['Identify affected asset, account and source','Verify timestamps and original evidence','Check approved business context','Escalate unresolved ambiguity'],
 'credential_access':['Verify account owner and authorized activity','Inspect credential-access process and parent lineage','Check follow-on authentication and access','Escalate suspected credential compromise'],
 'auth_failed':['Verify login source and account owner','Check successful logins after failures','Review MFA / authentication controls','Inspect post-login process and outbound activity'],
 'scan':['Identify scanner owner and approved scope','Check maintenance/pentest window','Inspect any post-scan authentication or execution','Record benign justification or escalate'],
 'process':['Verify executable, command and parent process','Confirm expected user/business activity','Inspect follow-on file and network activity','Record disposition and supporting evidence'],
 'network':['Verify source/destination and business purpose','Inspect associated process and user','Review adjacent authentication/network events','Escalate unexplained external communication'],
}

def enrich(incident):
    from . import store
    with store.connection() as conn:
        events=events_for(conn,incident['id'])
        row=conn.execute('SELECT * FROM incidents WHERE id=?',(incident['id'],)).fetchone()
        risk,benign=assess_risk(conn,row,events)
        hosts=sorted({e['host'] for e in events if e['host']!='unknown'}) or [incident['host']]
        users=sorted({e['user'] for e in events if e['user']!='unknown'})
        ips=sorted({e['src_ip'] for e in events if e['src_ip']})
        types=list(dict.fromkeys(e['kind'] for e in events))
        incident.update({'risk_explanation':risk,'score':risk['score'],'risk_band':risk['band'],'business_context':benign,
                         'asset':risk['asset'],
                         'event_count':len(events),'timeline':events,'affected_hosts':hosts,'observed_users':users,'source_ips':ips,'event_types':types})
        incident['asset_context']=[{'host':host,'criticality':incident['asset'],'observed_os':'Windows' if any('windows' in e['image'].lower() for e in events if e['host']==host) else 'Unknown',**context(conn,'asset',host)} for host in hosts]
        incident['user_context']=[]
        for user in users:
            related=conn.execute('SELECT data,epoch,incident_id FROM observed_events WHERE lower(user)=? AND kind IN (\'auth_failed\',\'auth_success\') ORDER BY epoch DESC LIMIT 20',(user.lower(),)).fetchall()
            incident['user_context'].append({'user':user,**context(conn,'user',user),'login_history':[{'time':r['epoch'],'incident_id':r['incident_id'],**{k:json.loads(r['data']).get(k) for k in ['kind','host','src_ip']}} for r in related]})
        incident['ip_context']=[]
        for ip in ips:
            stats=conn.execute('SELECT min(epoch),max(epoch),count(DISTINCT incident_id) FROM observed_events WHERE src_ip=?',(ip,)).fetchone()
            targets=[r[0] for r in conn.execute("SELECT DISTINCT host FROM observed_events WHERE src_ip=? AND host!='unknown' LIMIT 30",(ip,))]
            behavior=[dict(r) for r in conn.execute('SELECT kind,count(*) AS count,max(epoch) AS last_seen FROM observed_events WHERE src_ip=? GROUP BY kind ORDER BY count DESC LIMIT 6',(ip,))]
            incident['ip_context'].append({'ip':ip,'first_seen':stats[0],'last_seen':stats[1],'incidents':stats[2],'targets':targets,'behavior':behavior,'reputation':'unknown',**context(conn,'ip',ip)})
        current_signature=set(types)
        comparisons=[]
        # Bounded search by overlapping observed behavior; never imply all are equivalent.
        related=conn.execute('''SELECT i.id,i.title,i.decision,i.disposition,i.created,group_concat(DISTINCT e.kind) AS kinds
           FROM incidents i JOIN observed_events e ON e.incident_id=i.id WHERE i.id!=?
           GROUP BY i.id ORDER BY i.created DESC LIMIT 300''',(incident['id'],)).fetchall()
        for other in related:
            signature=set(other['kinds'].split(','));union=current_signature|signature
            similarity=len(current_signature&signature)/len(union) if union else 0
            if similarity>=.5:comparisons.append({**dict(other),'similarity':round(similarity,2)})
        incident['similar_incidents']={'matches':comparisons[:8],'total':len(comparisons),'benign':sum(x['disposition'] in {'benign_trigger','false_positive'} or x['decision']=='false_positive' for x in comparisons),
                                      'escalated':sum(x['decision']=='escalated' for x in comparisons),'scope':'At most 300 recent local incidents; shared event types, not confirmed equivalent attacks.'}
        baseline=[]
        for host in hosts:
            rows=conn.execute('SELECT epoch FROM observed_events WHERE host=? AND epoch IS NOT NULL ORDER BY epoch',(host,)).fetchall()
            counts=Counter(int(r[0]//86400) for r in rows)
            if counts:
                latest=max(counts);past=[n for day,n in counts.items() if day<latest]
                baseline.append({'host':host,'latest_day':latest*86400,'today_events':counts[latest],'history_days':len(past),
                                 'mean_events_per_observed_day':round(sum(past)/len(past),1) if past else None,
                                 'validated':False,'note':'Only ingested event days; not a complete SIEM baseline. At least 7 prior observed days recommended.'})
        incident['baseline']=baseline
        primary=next((kind for kind in ['credential_access','auth_failed','scan','process','network'] if kind in types),'generic')
        done={r['item']:dict(r) for r in conn.execute('SELECT * FROM checklist_items WHERE incident_id=?',(incident['id'],))}
        incident['playbook']=[{'item':item,'done':bool(done.get(item,{}).get('done')),'analyst':done.get(item,{}).get('analyst','')} for item in PLAYBOOKS[primary]]
        incident['notes']=[dict(r) for r in conn.execute('SELECT * FROM investigation_notes WHERE incident_id=? ORDER BY created DESC',(incident['id'],))]
        incident['response_requests']=[dict(r) for r in conn.execute('SELECT * FROM response_requests WHERE incident_id=? ORDER BY created DESC',(incident['id'],))]
        incident['correlation_explanation']={'rule':'Two shared anchors (host/user, host/source IP, user/source IP, or host/process identity), within a one-hour event span. Shared scan source can link victims within 10 minutes. Same-host technique fallback when identity is missing.',
                                           'entities':{'hosts':hosts,'users':users,'source_ips':ips},'retained_alerts':incident['alert_count'],'retained_events':len(events),
                                           'caveat':'Older incidents retain their original grouping; a shared entity is linkage, not proof of compromise.'}
        incident['correlation_explanation']['span_seconds']=max(e['epoch'] for e in events if e['epoch'] is not None)-min(e['epoch'] for e in events if e['epoch'] is not None) if any(e['epoch'] is not None for e in events) else None
        critical=[c for c in incident['asset_context'] if c.get('criticality') in {'high','critical'}]
        incident['why_care']=('A business-important asset is involved. ' if critical else 'Review the observed behavior and affected entities. ')+('All observed activity matches an approved business exception; verify its scope before closing.' if benign['classification']=='likely_benign' else 'Business justification or execution outcome may still be missing.')
        return incident

def model_context(incident_id):
    from . import store
    data=enrich(store.detail(incident_id))
    return {key:data[key] for key in ['asset_context','user_context','ip_context','business_context','correlation_explanation','why_care']}

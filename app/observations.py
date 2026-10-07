"""Observed event linkage. Every normalized event points back to an original span."""
import hashlib
import ipaddress
import json
import re
from .ingestion import extract

def pick(fields,*keys):
    return next((str(fields[k]).strip() for k in keys if fields.get(k) is not None and fields.get(k)!=''), '')

def address(value):
    try: return str(ipaddress.ip_address(value))
    except ValueError: return ''

def segments(raw):
    stripped=raw.lstrip();start=len(raw)-len(stripped)
    if stripped.startswith('['):
        decoder=json.JSONDecoder();pos=start+1;parts=[]
        try:
            while pos<len(raw):
                while pos<len(raw) and raw[pos] in ' \r\n\t,':pos+=1
                if pos>=len(raw) or raw[pos]==']':break
                begin=pos;value,pos=decoder.raw_decode(raw,pos)
                if not isinstance(value,dict):return [(0,len(raw),raw)]
                parts.append((begin,pos,raw[begin:pos]))
            return parts or [(0,len(raw),raw)]
        except ValueError:return [(0,len(raw),raw)]
    if stripped.startswith('<') and '<Event' in raw:
        parts=[(m.start(),m.end(),m.group()) for m in re.finditer(r'<Event\b[^>]*>.*?</Event>',raw,re.S)]
        if parts:return parts
    lines=raw.splitlines(keepends=True);pos=0;parts=[]
    try:
        for line in lines:
            if line.strip():
                if not isinstance(json.loads(line),dict):return [(0,len(raw),raw)]
                parts.append((pos,pos+len(line),line))
            pos+=len(line)
        return parts or [(0,len(raw),raw)]
    except ValueError:return [(0,len(raw),raw)]

def normalize(raw,host_override=''):
    result=[]
    for start,end,text in segments(raw):
        item=extract(text,host_override);fields=item['fields']
        src=address(pick(fields,'src_ip','sourceip','source_ip','src','id.orig_h','ipaddress','client_ip','source.ip'))
        dst=address(pick(fields,'dest_ip','destinationip','destination_ip','dst','id.resp_h','destination.ip','destip'))
        image=pick(fields,'image','imagefilename','process_name','process','executable','process.executable','process.name')
        command=pick(fields,'commandline','command_line','cmdline','process.command_line')
        parent=pick(fields,'parentimage','parentbasefilename','parent_process','process.parent.name')
        eventid=pick(fields,'eventid','event_id','event.code')
        signal=pick(fields,'event_type','action','signature','event_simplename','message').lower()
        lower=signal or (text[:500].lower() if not image and not command else '')
        kind='event';label=item['title']
        if eventid=='4625' or any(x in lower for x in ['failed login','login_failed','auth_failed','authentication failure']):kind='auth_failed';label='Failed authentication'
        elif eventid=='4624' or any(x in lower for x in ['successful login','login_success','auth_success','authentication success']):kind='auth_success';label='Successful authentication'
        elif lower=='scan' or any(x in lower for x in ['port scan','portscan','network scan','nmap','scan_detected']):kind='scan';label='Network scan observed'
        elif lower=='network' or eventid=='3' or any(x in lower for x in ['network connection','connection_established','outbound connection','network_connection']):kind='network';label='Network connection observed'
        elif eventid in {'11','23','26'}:kind='file';label='File activity observed'
        elif 'T1003.001' in item['hints']:kind='credential_access';label='Possible credential access'
        elif 'T1070.001' in item['hints']:kind='log_clear';label='Event-log clearing command'
        elif lower in {'dns','web','cloud'}:kind=lower;label={'dns':'DNS activity observed','web':'Web request observed','cloud':'Cloud API activity observed'}[lower]
        elif image or eventid=='1' or command or any(x in lower for x in ['processrollup','process start']):kind='process';label='Process started: '+(image.replace('\\','/').split('/')[-1] or 'command observed')
        if item['host']=='unknown' and dst:item['host']=dst
        if item['user']=='unknown':item['user']=pick(fields,'targetusername','targetuser','accountname','account','subjectusername') or 'unknown'
        result.append({**item,'src_ip':src,'dest_ip':dst,'image':image,'command':command,'parent':parent,'kind':kind,'label':label[:200],
                       'start':start,'end':end,'event_sha256':hashlib.sha256(text.encode()).hexdigest(),
                       'process_id':pick(fields,'processguid','processid','rawprocessid'),
                       'parent_process_id':pick(fields,'parentprocessguid','parentprocessid'),
                       'raw_fragment':text})
    return result

def initialize(conn):
    conn.executescript('''CREATE TABLE IF NOT EXISTS observed_events(
        id TEXT PRIMARY KEY,alert_id TEXT NOT NULL REFERENCES alerts(id),incident_id TEXT NOT NULL REFERENCES incidents(id),
        epoch REAL,host TEXT,user TEXT,src_ip TEXT,dest_ip TEXT,kind TEXT,technique TEXT,data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS event_incident ON observed_events(incident_id,epoch);
        CREATE INDEX IF NOT EXISTS event_host ON observed_events(host,epoch);
        CREATE INDEX IF NOT EXISTS event_source ON observed_events(src_ip,epoch);
        CREATE INDEX IF NOT EXISTS event_host_user ON observed_events(host COLLATE NOCASE,user COLLATE NOCASE,epoch);
        CREATE INDEX IF NOT EXISTS event_host_source ON observed_events(host COLLATE NOCASE,src_ip,epoch);
        CREATE INDEX IF NOT EXISTS event_user_source ON observed_events(user COLLATE NOCASE,src_ip,epoch);
        CREATE INDEX IF NOT EXISTS event_host_process ON observed_events(host COLLATE NOCASE,json_extract(data,'$.process_id') COLLATE NOCASE,epoch);
        CREATE TABLE IF NOT EXISTS evidence_links(event_id TEXT NOT NULL REFERENCES observed_events(id),kind TEXT NOT NULL,value TEXT NOT NULL,
          PRIMARY KEY(event_id,kind,value));
        CREATE INDEX IF NOT EXISTS link_entity ON evidence_links(kind,value);
        CREATE TABLE IF NOT EXISTS context_records(kind TEXT NOT NULL,entity TEXT NOT NULL,data TEXT NOT NULL,updated REAL NOT NULL,
          PRIMARY KEY(kind,entity));
        CREATE TABLE IF NOT EXISTS benign_rules(id TEXT PRIMARY KEY,name TEXT NOT NULL,entity_kind TEXT NOT NULL,entity_value TEXT NOT NULL,
          hosts TEXT NOT NULL,event_types TEXT NOT NULL,start REAL NOT NULL,end REAL NOT NULL,approved_by TEXT NOT NULL,reason TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS investigation_notes(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),analyst TEXT NOT NULL,note TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS checklist_items(incident_id TEXT NOT NULL REFERENCES incidents(id),item TEXT NOT NULL,done INTEGER NOT NULL,
          analyst TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(incident_id,item));
        CREATE TABLE IF NOT EXISTS response_requests(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id),kind TEXT NOT NULL,target TEXT NOT NULL,
          requested_by TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL,approved_by TEXT,created REAL NOT NULL);
    ''')
    if 'command_exact' not in {r['name'] for r in conn.execute('PRAGMA table_info(benign_rules)')}:
        conn.execute("ALTER TABLE benign_rules ADD COLUMN command_exact TEXT NOT NULL DEFAULT ''")
    # Reconstruct observable facts, preserving all original evidence and past groupings.
    rows=conn.execute('SELECT a.id,a.incident_id,a.raw FROM alerts a WHERE NOT EXISTS (SELECT 1 FROM observed_events e WHERE e.alert_id=a.id)').fetchall()
    for row in rows:insert_events(conn,row['id'],row['incident_id'],normalize(row['raw']))

def insert_events(conn,alert_id,incident_id,events):
    for index,event in enumerate(events):
        event_id=hashlib.sha256(f'{alert_id}:{index}'.encode()).hexdigest()[:32]
        data={k:v for k,v in event.items() if k not in {'raw_fragment','fields'}}
        conn.execute('INSERT INTO observed_events VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                     (event_id,alert_id,incident_id,event['epoch'],event['host'],event['user'],event['src_ip'],event['dest_ip'],event['kind'],event['hints'][0] if event['hints'] else '',json.dumps(data)))
        entities={'host':event['host'],'user':event['user'],'source_ip':event['src_ip'],'destination_ip':event['dest_ip'],'process':event['image'],
                  'process_id':event['host']+':'+event['process_id'] if event['process_id'] else '',
                  'parent_process_id':event['host']+':'+event['parent_process_id'] if event['parent_process_id'] else '',
                  'technique':event['hints'][0] if event['hints'] else ''}
        for kind,value in entities.items():
            if value and value!='unknown':conn.execute('INSERT OR IGNORE INTO evidence_links VALUES (?,?,?)',(event_id,kind,value.lower()))

def correlate(conn,events):
    usable=[e for e in events if e['epoch'] is not None]
    if not usable:return None
    earliest=min(e['epoch'] for e in usable);latest=max(e['epoch'] for e in usable)
    if latest-earliest>3600:return None
    first=usable[0]
    candidates=conn.execute('''SELECT DISTINCT i.* FROM incidents i JOIN observed_events e ON e.incident_id=i.id
       WHERE i.decision='unreviewed' AND i.status!='analyzing' AND abs(i.first_event-?)<=3600 AND abs(i.last_event-?)<=3600
       AND ((e.host=? COLLATE NOCASE AND e.user=? COLLATE NOCASE AND ?!='unknown' AND ?!='unknown')
         OR (e.host=? COLLATE NOCASE AND e.src_ip=? AND ?!='unknown' AND ?!='')
         OR (e.user=? COLLATE NOCASE AND e.src_ip=? AND ?!='unknown' AND ?!='')
         OR (e.host=? COLLATE NOCASE AND json_extract(e.data,'$.process_id')=? COLLATE NOCASE AND ?!='unknown' AND ?!='')
         OR (e.src_ip=? AND e.kind='scan' AND ?='scan' AND ?!=''))
       ORDER BY i.created DESC LIMIT 20''',(earliest,latest,first['host'],first['user'],first['host'],first['user'],
       first['host'],first['src_ip'],first['host'],first['src_ip'],first['user'],first['src_ip'],first['user'],first['src_ip'],
       first['host'],first['process_id'],first['host'],first['process_id'],first['src_ip'],first['kind'],first['src_ip'])).fetchall()
    for candidate in candidates:
        if max(candidate['last_event'],latest)-min(candidate['first_event'],earliest)>3600:continue
        if first['kind']=='scan' and first['user']=='unknown' and first['host'].lower()!=candidate['host'].lower():
            if max(candidate['last_event'],latest)-min(candidate['first_event'],earliest)>600:continue
        # Do not bridge a submitted envelope containing conflicting identities through just its first event.
        known_hosts={e['host'] for e in events if e['host']!='unknown'}
        if len(known_hosts)>1:return None
        return candidate
    return None

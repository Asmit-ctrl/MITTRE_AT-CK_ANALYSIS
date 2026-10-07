"""Read bounded public Splunk file prefixes; retain source offsets and hashes."""
import hashlib,json,re,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REV='4389fa7a4e74a7c083c0fbe448fa2c7c32378981'
SOURCES=[
 ('authentication','T1078.002/account_login/windows-security.log'),
 ('brute_force','T1110/esxi_ssh_brute_force/esxi_ssh_brute_force.log'),
 ('scan','T1046/nmap/horizontal.log'),
 ('powershell','T1059.001/atomic_red_team/captcha_windows-sysmon.log'),
 ('endpoint','T1070/atomic_red_team/windows-sysmon.log'),
 ('credential','T1003.001/atomic_red_team/createdump_windows-sysmon.log'),
 ('dns','T1071.004/long_dns_query/dns-sysmon.log'),
 ('cloud','T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json'),
 ('privilege','T1068/drivers/xml7045_windows-system.log')]
def main():
 dest=ROOT/'data'/'demo';dest.mkdir(exist_ok=True)
 tree=json.loads((ROOT/'.runtime/splunk-tree.json').read_text())
 web=next((x['path'] for x in tree['tree'] if x['path'].startswith('datasets/attack_techniques/T1190/') and ('nginx' in x['path'] or 'apache' in x['path']) and x['path'].endswith('.log')),None)
 sources=SOURCES+([('web',web.split('datasets/attack_techniques/')[1])] if web else [])
 records=[];manifest=[]
 for category,suffix in sources:
  path='datasets/attack_techniques/'+suffix;url=f'https://media.githubusercontent.com/media/splunk/attack_data/{REV}/{path}'
  try:
   with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Shiftline'}),timeout=45) as response: chunk=response.read(1_500_000)
   text=chunk.decode('utf-8',errors='replace');events=[]
   if '<Event' in text:
    events=[(m.start(),m.group()) for m in re.finditer(r'<Event(?:\s|>).*?</Event>',text,re.S)]
   elif 'windows-security' in suffix and re.search(r'^\d{1,2}/\d{1,2}/\d{4} ',text,re.M):
    starts=[m.start() for m in re.finditer(r'^\d{1,2}/\d{1,2}/\d{4} ',text,re.M)]
    events=[(a,text[a:b]) for a,b in zip(starts,starts[1:])]
   else:
    pos=0
    for line in text.splitlines(keepends=True):
     if line.strip():
      try:
       obj=json.loads(line)
       if isinstance(obj,dict):events.append((pos,line))
      except ValueError:
       if len(line)<16000:events.append((pos,line))
     pos+=len(line)
    if not events:
     try:
      obj=json.loads(text)
      entries=obj if isinstance(obj,list) else obj.get('Records',[]) if isinstance(obj,dict) else []
      events=[(None,json.dumps(x)) for x in entries if isinstance(x,dict)]
     except ValueError:pass
   usable=[(off,raw) for off,raw in events if len(raw)<16000][:160]
   source={'category':category,'path':path,'revision':REV,'url':f'https://github.com/splunk/attack_data/blob/{REV}/{path}','prefix_sha256':hashlib.sha256(chunk).hexdigest(),'read_bytes':len(chunk),'events':len(usable)}
   manifest.append(source)
   for off,raw in usable:records.append({'category':category,'raw':raw,'source':source,'source_offset':off,'original_sha256':hashlib.sha256(raw.encode()).hexdigest()})
   print(category,len(usable))
  except Exception as exc:print(category,type(exc).__name__)
 (dest/'pool.json').write_text(json.dumps(records),encoding='utf-8')
 (dest/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
 if len(records)<260:raise RuntimeError('Demo pool needs at least 260 distinct public events')
if __name__=='__main__':main()

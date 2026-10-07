import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.main import analysis

try:
    items=analysis.retrieve(analysis.RetrievalPlan(technique_ids=['T1059.001','T1003.001']))
    print(json.dumps([{'id':x['id'],'name':x['name'],'context_count':len(x['context'])} for x in items]))
except Exception as exc:
    print('Retrieval failed: '+type(exc).__name__)
    if type(exc).__name__=='CypherSyntaxError': print(str(exc))
    raise SystemExit(1)
finally:
    if analysis.graph.cache_info().currsize: analysis.graph().close()

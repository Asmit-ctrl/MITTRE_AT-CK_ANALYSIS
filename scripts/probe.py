"""Read-only connection/schema check. Never prints credentials or raw exceptions."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
from neo4j import GraphDatabase
from openai import OpenAI

load_dotenv(Path(__file__).resolve().parents[1] / '.env')
if '--graph' in sys.argv:
    try:
        with GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USERNAME'], os.environ['NEO4J_PASSWORD']), connection_timeout=15, max_transaction_retry_time=5) as driver:
            driver.verify_connectivity()
            records, _, _ = driver.execute_query('MATCH (n) UNWIND labels(n) AS label RETURN label, count(*) AS count ORDER BY count DESC LIMIT 20', database_=os.environ['NEO4J_DATABASE'], routing_='r')
            print(json.dumps([r.data() for r in records]))
            records, _, _ = driver.execute_query('MATCH (n) WHERE any(k IN keys(n) WHERE toString(n[k]) = $id) RETURN labels(n) AS labels, properties(n) AS properties LIMIT 2', id='T1059.001', database_=os.environ['NEO4J_DATABASE'], routing_='r')
            print(json.dumps([r.data() for r in records], default=str)[:10000])
    except Exception as exc:
        print('Graph probe failed: ' + type(exc).__name__)
if '--llm' in sys.argv:
    try:
        client = OpenAI(base_url='https://integrate.api.nvidia.com/v1', api_key=os.environ['NVIDIA_API_KEY'], timeout=45, max_retries=0)
        answer = client.chat.completions.create(model=os.environ['NVIDIA_MODEL'], messages=[{'role': 'user', 'content': 'Return only {"ok":true} as JSON.'}], temperature=0, max_tokens=100, extra_body={'chat_template_kwargs': {'enable_thinking': False}})
        print('LLM probe: ' + (answer.choices[0].message.content or '(empty)'))
    except Exception as exc:
        print('LLM probe failed: ' + type(exc).__name__)

import sqlite3
from pathlib import Path
count=0
for name in ['triage','demo','lab']:
    path=Path(__file__).resolve().parents[1]/'data'/(name+'.db')
    if path.exists():
        with sqlite3.connect(path) as conn:
            count+=conn.execute("SELECT count(*) FROM incidents WHERE status='analyzing'").fetchone()[0]
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='workbench_jobs'").fetchone():
                count+=conn.execute("SELECT count(*) FROM workbench_jobs WHERE status IN ('running','queued')").fetchone()[0]
print(count)

"""Publish the staged Tier-1 files into this checkout after validation."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
stage=ROOT/'.runtime'/'frontend'
code=(stage/'app.js').read_text(encoding='utf-8')
replacements={
    '<div class="summary">${brief(d)}</div>':'<div class="summary">${brief(d)}</div>${a?.coverage_note?`<p class="section-note">${esc(a.coverage_note)}</p>`:""}',
    "${draft.disposition===x?'selected':''}":"${(closed?d.disposition:draft.disposition)===x?'selected':''}",
    "${fact('Targeted assets',x.targets.join(', '))}":"${fact('Targeted assets',x.targets.join(', '))}${fact('Observed behavior',x.behavior?.map(b=>label(b.kind)+' · '+b.count).join(', '))}",
}
for old,new in replacements.items():
    if new in code:continue
    if old not in code:raise RuntimeError('Expected UI fragment is missing')
    code=code.replace(old,new)
coverage='${a?.coverage_note?`<p class="section-note">${esc(a.coverage_note)}</p>`:""}'
while coverage+coverage in code:code=code.replace(coverage+coverage,coverage)
claim_status="function claimStatus(c){return /\\b(indicating|suggest\\w*|likely|potential|possible|suspicious|compromise|was requested)\\b/i.test(c.text)?'suspected':c.status;}\n"
if 'function claimStatus(' not in code:code=code.replace('function brief(d){',claim_status+'function brief(d){')
code=code.replace('class="claim-status ${esc(c.status)}">${esc(c.status)}','class="claim-status ${esc(claimStatus(c))}">${esc(claimStatus(c))}')
code=code.replace('<div class="playbook"><div class="section-label">INVESTIGATION CHECKLIST</div>',
                  '<details class="playbook"><summary>Investigation checklist · ${d.playbook.filter(x=>x.done).length}/${d.playbook.length}</summary>')
code=code.replace("${esc(x.item)}</label>`).join('')}</div><div class=\"analyst-form\">",
                  "${esc(x.item)}</label>`).join('')}</details><div class=\"analyst-form\">")
if "${b.facts?.length?" not in code:
    code=code.replace("${b.partial_matches?.length?", "${b.facts?.length?`<p>${b.facts.map(esc).join(' ')}</p>`:''}${b.partial_matches?.length?")
(stage/'app.js').write_text(code,encoding='utf-8')
for name in ['index.html','style.css','app.js']:
    (ROOT/'static'/name).write_bytes((stage/name).read_bytes())
print('Tier-1 interface published locally.')

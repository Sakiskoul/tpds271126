"""Summarize actual engine rows only. No synthetic fallback or hidden failures."""
import argparse,csv,statistics,collections,math,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('run');a=p.parse_args();root=Path(a.run);rows=list(csv.DictReader((root/'trials.csv').open()));env=json.loads((root/'environment.json').read_text());assert env['engine_version'] and env['engine_sha256']
g=collections.defaultdict(list)
for r in rows:g[tuple(r[k] for k in ('nodes','workers','policy','scenario','batch'))].append(r)
def pct(v,p):return sorted(v)[max(0,math.ceil(p*len(v))-1)] if v else ''
res=[]
for keys,rs in sorted(g.items()):
    good=[r for r in rs if r['outcome']=='finalized'];v=[int(r['finality_ns'])/1e6 for r in good];e=[int(r['elapsed_ns'])/1e9 for r in rs]
    res.append(dict(zip(('nodes','workers','policy','scenario','batch'),keys))|dict(attempts=len(rs),finalized=len(good),errors=sum(r['outcome']=='error_or_timeout' for r in rs),no_certificate=sum(r['outcome']=='no_certificate' for r in rs),checktx_rejected=sum(r['outcome']=='checktx_rejected' for r in rs),median_ms=statistics.median(v) if v else '',empirical_p95_ms=pct(v,.95),empirical_p99_ms=pct(v,.99),confirmed_items_per_attempt_second=len(good)*int(keys[-1])/sum(e) if sum(e)>0 else ''))
with (root/'engine_summary.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=list(res[0]));w.writeheader();w.writerows(res)
print('Cells',len(res),'attempts',len(rows),'finalized',sum(r['finalized'] for r in res))

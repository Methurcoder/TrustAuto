"""Diagnostic only: limits read off the test rows, so these are ceilings, not results."""
import json,sys
import numpy as np
sys.argv=[sys.argv[0],sys.argv[1]]
S=sys.argv[1]
ALLOW={'harmless','teacher_allow'}
def load(model,split,seed):
    d=f'{S}/ext/m4' if seed==1 else f'{S}/ext/seeds/s{seed}'
    return {(r['machine'],r['id']):r for r in map(json.loads,open(f'{d}/scores/{model}_{split}.jsonl'))}
def curve(members,label):
    base=members[0]
    mean={k:float(np.mean([m[k]['score'] for m in members])) for k in base}
    risky=sorted(((mean[k],r['group']) for k,r in base.items() if r['final']=='risky'))
    hs=np.array([mean[k] for k,r in base.items() if r['final'] in ALLOW])
    out=[]
    for want in (0,1,2,4):
        seen=set(); t=None
        for s,g in risky:
            if g not in seen and len(seen)==want: t=s;break
            seen.add(g)
        out.append(f"miss {want}: {100*(hs<t).mean():.1f}%")
    print(f"{label:50s}",' | '.join(out))
F,E,G='known_facts_transformer','known_ext_facts_transformer','known_ext_general_facts_transformer'
for split in ('machine','target'):
    print('==',split)
    for m in (F,E,G):
        for s in (1,2,3,4): curve([load(m,split,s)],f'{m} s{s}')
        curve([load(m,split,s) for s in (1,2,3,4)],f'{m} mean of 4')
    curve([load(m,split,s) for m in (F,E,G) for s in (1,2,3,4)],'mean of 12')

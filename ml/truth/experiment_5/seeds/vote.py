"""Post-hoc: auto-allow only when every member allows, each at its own inside-train limit. Reads existing score files."""
import json,sys,itertools
S=sys.argv[1]
ALLOW={'harmless','teacher_allow'}
def load(model,split,seed):
    d=f'{S}/ext/m4' if seed==1 else f'{S}/ext/seeds/s{seed}'
    return {(r['machine'],r['id']):r for r in map(json.loads,open(f'{d}/scores/{model}_{split}.jsonl'))}
def ub(k,n):
    lo,hi=0.0,1.0
    from math import comb
    for _ in range(60):
        m=(lo+hi)/2
        c=sum(comb(n,i)*m**i*(1-m)**(n-i) for i in range(k+1))
        lo,hi=(m,hi) if c>0.05 else (lo,m)
    return hi
def ev(members,label):
    base=members[0]; rows=list(base.values())
    ok=lambda key:all(m[key]['score']<m[key]['limit'] for m in members)
    risky=[(k,r) for k,r in base.items() if r['final']=='risky']
    groups={r['group'] for k,r in risky}; miss={r['group'] for k,r in risky if ok(k)}
    harm=[(k,r) for k,r in base.items() if r['final'] in ALLOW]
    un=[(k,r) for k,r in harm if not r['changed']]; ch=[(k,r) for k,r in harm if r['changed']]
    p=sum(ok(k) for k,r in harm); rev=[(k,r) for k,r in base.items() if r['final']=='review']
    print(f"{label:58s} risky {len(miss):2d}/{len(groups)} UB {100*ub(len(miss),len(groups)):4.1f}%  harmless {100*p/len(harm):5.1f}% un {sum(ok(k) for k,r in un)}/{len(un)} ch {sum(ok(k) for k,r in ch)}/{len(ch)} review {sum(ok(k) for k,r in rev)}/{len(rev)}")
    return sorted(miss)
F,E,G,B='known_facts_transformer','known_ext_facts_transformer','known_ext_general_facts_transformer','known_ext_boost'
for split in ('machine','target'):
    print('==',split)
    for model in (F,E,G):
        for s in (1,2,3,4): ev([load(model,split,s)],f'{model} seed{s}')
        ev([load(model,split,s) for s in (1,2,3,4)],f'{model} all 4 seeds agree')
    ev([load(B,split,1)],f'{B}')
    ev([load(m,split,s) for m in (F,E,G) for s in (1,2,3,4)],'12 transformers agree')
    m=ev([load(m,split,s) for m in (F,E,G) for s in (1,2,3,4)]+[load(B,split,1)],'12 transformers + boost agree')
    print('   missed groups:',m[:30])

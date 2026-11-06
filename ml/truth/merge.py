import json,sys,collections,re,os
S=sys.argv[1]
load=lambda n:[json.loads(l) for l in open(f"{S}/{n}.jsonl")]
base={' '.join(r['case']):r for r in load('results')}
rerun=load('rerun')
for r in rerun: base[' '.join(r['case'])]=r
errs=[k for k,r in base.items() if 'error' in r]
print('errors',errs[:10])
def bad(r): return sorted(k for k,v in r['checks'].items() if not v)
c1={' '.join(r['case']):bad(r) for r in load('confirm1') if 'checks' in r}
c2={' '.join(r['case']):bad(r) for r in load('confirm2') if 'checks' in r}
final={}
rem_status=collections.Counter()
for k,r in base.items():
    a=r['action'];t=a.get('tail','')
    st='applied'
    if r['case'][0]=='remove' and a['rc']!=0:
        if 'conflicting assignments' in t: st='refused'
        elif 'Sub-process' in t: st='dpkg_error'
        elif 'Solver timed out' in t: st='solver_timeout'
        elif 'Unable to fetch' in t: st='no_network'
        else: st='harness'
    if r['case'][0]=='remove': rem_status[st]+=1
    b=bad(r)
    final[k]=dict(status=st,bad=b,rc=a['rc'],removed=a.get('removed',[]),before=a.get('before'),after=a.get('after'))
print(rem_status)
# rerun broken not yet confirmed
new=[k for k in (' '.join(r['case']) for r in rerun) if final[k]['bad']]
print('broken among rerun',len(new))
for k in new: print(' ',k,final[k]['status'],len(final[k]['removed']),final[k]['bad'])
print('--- confirmation of first-pass broken: first | c1 | c2')
for k in c1:
    print(' ',k,final[k]['bad'],'|',c1[k],'|',c2.get(k))
for k in [k for k,v in final.items() if v['status'] in('harness','no_network','dpkg_error','solver_timeout')]:
    print(' NOTAPPLIED',k,final[k]['status'],len(final[k]['removed']),final[k]['bad'], base[k]['action'].get('tail','')[-160:].replace('\n',' / ') if final[k]['status'] in ('harness','no_network') else '')
json.dump(final,open(f"{S}/merged.json",'w'))

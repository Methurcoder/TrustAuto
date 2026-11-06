import json,pathlib,sys,collections
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))  # ml/truth
import teach_gemini as tg
S,model=pathlib.Path(sys.argv[1]),sys.argv[2]
out=S/'agy/flash_try'/model
tab=collections.Counter(); diff=[]; first={}
for path in sorted(out.glob('*.txt')):
    turn,m,b=path.stem.split('_'); b=int(b)
    man=json.loads((S/f'agy/full_{m}/manifest.json').read_text())
    labs={r['id']:r for r in map(json.loads,open(S/f'act/final/lab_{m}.jsonl'))}
    group=tg.batches(len(man['ids']),man['batch'])[b-1]
    rows={i:labs.get(man['ids'][i]) for i in group}
    new=tg.read_answer(path.read_text(),set(group))
    old=tg.read_answer((S/f'agy/full_{m}/answer_{b:03}.txt').read_text(),set(group))
    print(path.stem,'answered',len(new),'/',len(group),'argon',len(old))
    if int(turn)==6:
        same=sum(first[(m,b,i)]==new[i]['decision'] for i in new if (m,b,i) in first)
        print('repeat of first batch: same',same,'/',len(new)); continue
    for i in group:
        r=rows[i]
        if i not in new or r is None: continue
        first[(m,b,i)]=new[i]['decision']
        kind='planted' if tg.is_danger(r) else r['label']
        tab[(kind,'flash',new[i]['decision'])]+=1
        if i in old:
            tab[(kind,'argon',old[i]['decision'])]+=1
            tab[(kind,'agree' if old[i]['decision']==new[i]['decision'] else 'differ','')]+=1
            if old[i]['decision']!=new[i]['decision']:
                diff.append((kind,old[i]['decision'],new[i]['decision'],' '.join(r['argv'])[:70],new[i]['reason'][:70]))
for k in sorted(tab): print(k,tab[k])
for d in diff: print(d)

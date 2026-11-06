"""Sends batches Argon already answered to another model. No row here is new to Gemini."""
import json,pathlib,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))  # ml/truth
import teach_gemini as tg
S,model=pathlib.Path(sys.argv[1]),sys.argv[2]
out=S/'agy/flash_try'/model; out.mkdir(parents=True,exist_ok=True)
PLAN=[('ubu2610',1),('ubu2610',4),('ubu2610',7),('ubu2610',10),('deb137',3),('deb137',9),('ubu2610',1)]
with tempfile.TemporaryDirectory() as tmp:
    settings,empty=pathlib.Path(tmp)/'settings.json',pathlib.Path(tmp)/'empty'
    settings.write_text(json.dumps(tg.DENY_TOOLS)); empty.mkdir()
    for turn,(m,b) in enumerate(PLAN):
        text=(S/f'agy/full_{m}/batch_{b:03}.txt').read_text()
        t=time.monotonic(); said=tg.ask(text,str(pathlib.Path.home()/'.local/bin/agy'),settings,empty,model,timeout=600)
        problem=tg.why_unusable(said)
        (out/f'{turn}_{m}_{b:03}.txt').write_text(said['reply'])
        print(json.dumps({'turn':turn,'machine':m,'batch':b,'problem':problem,'seconds':round(time.monotonic()-t),'thinking':said['thinking'],'tools':said['tools'],'status':said['status']}),flush=True)
        time.sleep(2)

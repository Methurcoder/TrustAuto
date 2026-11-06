import json,subprocess,pathlib,glob,os
# File lists per package, and the unit properties a decision could read.
lists={}
for p in glob.glob("/var/lib/dpkg/info/*.list"):
    n=os.path.basename(p)[:-5].split(":")[0]
    lists[n]=[l.strip() for l in open(p,errors="replace") if l.strip() and not os.path.isdir(l.strip())]
units={}
for line in open("units.txt"):
    u=line.strip()
    if not u: continue
    o=subprocess.run(["systemctl","show",u],capture_output=True,text=True).stdout
    units[u]=dict(x.split("=",1) for x in o.splitlines() if "=" in x)
    # The unit file itself, because some properties only show up there.
    fp=units[u].get("FragmentPath","")
    units[u]["_text"]=open(fp,errors="replace").read()[:4000] if fp and os.path.exists(fp) else ""
json.dump({"lists":lists,"units":units},open("facts.json","w"))
print(len(lists),len(units))

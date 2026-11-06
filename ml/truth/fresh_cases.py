import pathlib
r=lambda n:set(pathlib.Path(n).read_text().split())
pk=sorted(r('pkgs_after.txt')-r('pkgs_before.txt'))
old_cases=[l.split() for l in open('cases_all.txt')]
old_u={c[1] for c in old_cases if c[0]!='remove'}
un=sorted(r('units_after.txt')-r('units_before.txt')-old_u)
pathlib.Path('new_pkgs.txt').write_text('\n'.join(pk)+'\n'); pathlib.Path('new_units.txt').write_text('\n'.join(un)+'\n')
pathlib.Path('cases_fresh.txt').write_text(''.join(f'remove {p}\n' for p in pk)+''.join(f'{v} {u}\n' for u in un for v in('stop','restart')))
pathlib.Path('rerun.txt').write_text(''.join(f'remove {p}\n' for p in pk))
print(len(pk),len(un))

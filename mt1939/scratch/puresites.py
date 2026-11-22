import sys; sys.argv=[sys.argv[0],"30"]
sys.path.insert(0,"/work/re")
import io, contextlib
buf=io.StringIO()
with contextlib.redirect_stdout(buf):
    import uhdsites2 as U
pure=[]
for a,k in U.sites:
    if U.c8class_nearby(a, 24): continue
    # also skip ==C7 that directly follows a >>2==32 test (pair) -- keep the >>2 one
    pure.append((a,k))
fns={}
for a,k in pure:
    f=U.fstart(a); mm,calls,notes=U.window(a)
    fns.setdefault(f,[]).append((a,k,mm,notes,calls))
for f in sorted(fns):
    items=fns[f]
    mm=sorted({m for it in items for m in it[2]}); notes=sorted({n for it in items for n in it[3]})
    print(f"fn {f:#09x}: {len(items)} pure site(s) {[hex(i[0]) for i in items][:6]} mmio {mm} {' '.join(notes)}")

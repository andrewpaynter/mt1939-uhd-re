import sys; sys.path.insert(0,"/work"); sys.path.insert(0,__import__("os").path.dirname(__import__("os").path.abspath(__file__))+"/.."); from logparse import records
from collections import Counter
def new(before, after):
    b=open(before,"rb").read(); a=open(after,"rb").read()
    diff=[i for i in range(len(a)) if a[i]!=b[i]]
    if not diff: return []
    lo,hi=min(diff),max(diff)
    return [r for r in records(a) if lo-8<=r[0]<=hi]
if __name__=="__main__":
    recs=new(sys.argv[1],sys.argv[2])
    c=Counter(code>>16 for _,code,_ in recs)
    print(len(recs),"new records")
    for ev in ("11b9","11bb","11be","12eb","12ec","12ee","12ef","12c8","1d16","0ddd","0de5","23cf","2017"):
        print(f"  {ev}: {c.get(int(ev,16),0)}")

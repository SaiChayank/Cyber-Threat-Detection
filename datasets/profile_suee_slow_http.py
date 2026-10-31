"""Profile the SUEE1 slow-HTTP capture (Ulm, 2017): ordering, attacker connection lifetimes and rates.

Usage: python -m datasets.profile_suee_slow_http data/raw/suee-20261101/SUEE1.pcap
"""
import sys
from pathlib import Path
from collections import defaultdict
import statistics as st
from datasets.evaluate_lab import read_events


def main(path):
    prev=None; back=0; maxback=0; conns=defaultdict(lambda:[None,0,0,0]); n=0; ts=[]
    for e in read_events(Path(path),{}):
        n+=1
        if prev is not None and e.timestamp<prev:
            back+=1; maxback=max(maxback,prev-e.timestamp)
        prev=e.timestamp
        if str(e.src_ip).startswith('10.128.0.') and e.dst_port==80:
            c=conns[(str(e.src_ip),e.src_port)]
            c[0]=e.timestamp if c[0] is None else c[0]; c[1]=e.timestamp; c[2]+=e.bytes; c[3]+=1
    print('events',n,'backward steps',back,'max back ms',maxback)
    d=[(c[1]-c[0])/1000 for c in conns.values()]; r=[c[2]/max((c[1]-c[0])/1000,1) for c in conns.values()]
    print('connections',len(conns),'duration s med/p90/max',st.median(d),sorted(d)[int(.9*len(d))],max(d))
    print('rate Bps med/p90',st.median(r),sorted(r)[int(.9*len(r))],'pkts med',st.median(c[3] for c in conns.values()))
    print('conns >=30s',sum(x>=30 for x in d),'and <100Bps',sum(1 for x,y in zip(d,r) if x>=30 and y<100))


if __name__ == '__main__':
    main(sys.argv[1])

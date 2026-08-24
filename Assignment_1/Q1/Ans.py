
import asyncio
asyncio.set_event_loop(asyncio.new_event_loop())

if not hasattr(asyncio, 'set_child_watcher'):
    asyncio.SafeChildWatcher = type('SafeChildWatcher', (), {'attach_loop': lambda *a: None})
    asyncio.set_child_watcher = lambda *a, **k: None
    asyncio.get_child_watcher = lambda *a, **k: asyncio.SafeChildWatcher()


import pyshark
from collections import Counter

cap = pyshark.FileCapture('challenge.pcap', keep_packets=False)

total = 0
protos = Counter()
ip_src = set()
arp_req = []          
arp_rep = set()       
hosts = {}            
def h(ip):
    return hosts.setdefault(ip, dict(mac=None, sent=0, recv=0, replied=False, targeted=False))

for pkt in cap:
    total += 1
    protos[pkt.highest_layer] += 1

    if 'ARP' in pkt:
        a = pkt.arp
        spa, tpa = a.src_proto_ipv4, a.dst_proto_ipv4
        h(spa)['mac'] = a.src_hw_mac
        if a.opcode == '1':
            arp_req.append((pkt.number, spa, tpa))
            h(tpa)['targeted'] = True
        elif a.opcode == '2':
            arp_rep.add(spa)
            h(spa)['replied'] = True

    elif 'IP' in pkt:
        s, d = pkt.ip.src, pkt.ip.dst
        ip_src.add(s)
        h(s)['sent'] += 1
        h(d)['recv'] += 1
        h(s)['mac'] = pkt.eth.src

cap.close()

unans = [r for r in arp_req if r[2] not in arp_rep]
missing = [ip for ip, v in hosts.items() if v['targeted'] and not v['replied']]
gw = [ip for ip, v in hosts.items()
      if v['replied'] and v['sent'] == 0 and v['recv'] == 0]

print( total)
print(dict(protos))
print([(ip, hosts[ip]['mac']) for ip in gw])
print(len(ip_src), sorted(ip_src))
print( missing)
print(len(unans), unans)


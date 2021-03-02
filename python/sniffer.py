#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt): 
	pkt.show()
	
#pkt = sniff(iface='enp0s3' ,filter = 'icmp', prn=print_pkt) 
pkt = sniff(iface='enp0s3' , filter = 'tcp and host 10.0.2.15 and dst port 23', prn=print_pkt)
#pkt = sniff(iface='enp0s3' , filter = 'net 128.230.0.0/16', prn=print_pkt)


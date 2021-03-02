#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

#pkt = sniff(iface='br-db6353d0110f', prn=print_pkt) #sniff through seed
pkt = sniff(iface='enp0s3:', prn=print_pkt) #sniff through VM


from scapy.all import *

a=IP()
a.dst = '10.0.2.3'
b = ICMP()
p=a/b
send(p)
print("lis(a) : ")
ls(a)

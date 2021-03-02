from scapy.all import *
a = IP()
a.dst = '34.96.118.58'
a.ttl = 1
b = ICMP()
send(a/b)

for i in range(16):
	a.ttl = i
	send(a/b)





from scapy.all import *

import threading

running = True
requestBuffer = []
me = "192.168.0.16"
DNSServer = "8.8.8.8"
#me = sys.argv[0]

def DNSQuery(domainName):
	name = str(domainName)
	query = IP(dst=DNSServer)/UDP()/DNS(rd=1, qd=DNSQR(qname=name, qtype="AAAA"))
	response = sr1(query)
	for r in response[2].an:
		if r.type == "AAAA":
			return str(r.rdata)




class connectionListener (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run (self):
		print "Started listening"
		while running:
			request = sniff(filter="port 53", count=1, iface="eth0", promisc=1, timeout=1)
			if len(request) < 1: continue
			if not request[0].haslayer(DNS) or request[0].qr: continue
			if request[0].src = me: continue
			self.connList.append(request[0])



class translator (threading.Thread):
	def __init__ (self, request):
		self.request = request
		threading.Thread.__init__(self)

	def run (self):
		domainName = request[2].qd.qname
		lookupIP = DNSQuery(domainName)
		if not lookupIP is None: return
		
# I don't even know...






class runner (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run (self):
		while running:
			try:
				request = self.connList.pop(0)
				t = translator(request)
				t.start()
			except IndexError:
				continue




requestListener = connectionListener(requestBuffer)
requestListener.start()

translatorRunner = runner(requestBuffer)
translatorRunner.start()

while 1:
	try:
		pass
	except KeyboardInterrupt:
		running = False
		print "\nGoodbye"
		break



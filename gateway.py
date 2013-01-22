try:
    import scapy
except ImportError:
    del scapy
    from scapy import all as scapy

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
		while running:
			request = sniff(filter="tcp and port 80", count=1, iface="eth0")
			self.connList.append(request)



class translator (threading.Thread):
	def __init__ (self, request):
		self.request = request
		threading.Thread.__init__(self)

	def run (self):
		# check if meant for me
		if request.src == me:
			# check if meant for IPv6 - via DNS lookup
			domainName = request[2].qd.qname
			lookupIP = DNSQuery(domainName)
			if request.dst == lookupIP:
				# check that it's not already mapped
				
					# set as mapped
					
					# get content from v6 server
					
					# send back to v4 client
					
					# close connections-ish
		
		# I don't even know...
		



class runner (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run (self):
		while running:
			request = connList.pop(0)
			t = translator(request)
			t.start()




requestListener = connectionListener(requestBuffer)
requestListener.start()

translatorRunner = runner(requestBuffer)
translatorRunner.start()

while 1:
	pass



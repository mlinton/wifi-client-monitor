from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
from datetime import datetime, timedelta

interface = 'wlan0'
m_finished = False
CurrentStations = {}

def sniffProbe(pkt):
    #pkt.show()
    StationName = pkt.addr2
    if CurrentStations.has_key(StationName):
    	DwellTime = (datetime.now()-CurrentStations[StationName])
    	print '[-] Time since '  + StationName + ' last detected: ' + str(DwellTime) + ' SSID: ' + str(pkt.info) + '\r',
    	CurrentStations[StationName] = datetime.now()
    else:
    	CurrentStations[StationName] = datetime.now()
        print '[+] Detected New Station: ' + StationName +  ' SSID: ' + str(pkt.info) + ' Detected at: ' + datetime.now().strftime('%a, %d %b %Y %H:%M:%S')
        	
def threaded_sniff_target(q):
	global m_finished
	sniff(iface=interface, lfilter = lambda x: (x.haslayer(Dot11ProbeReq)), prn= lambda x : q.put(x))
	#m_finished = True
	
#def sniffLog():
	#read and write log data from the sniffing log / db
	#sqlite3? or flat file
	
#def whitelist():
	#provide the capability to whitelist addresses from alerter
	#if address in whitelist detected
	
#def alerter():
	#provide a method to alert of a newly detected wifi with a dwell time exceeding the max
	
#measure signal strength
	#how to get the signal strength out of the packet?
	#how to calculate relative signal strength (is the station getting stronger or weaker?)
	#can this be used to determine proximity?
	
#manage the lists of unknown addresses
	#associated with a home address?
	#association with other stations that share the same proberequest (could be common households/businesses)
	
#channel hopping code

#def display a list of the dwelling macs
	#time now - time last seen (filter after x time)


#main thread - will exit on control-c
def threaded_sniff():
	q = Queue()
	sniffer = Thread(target = threaded_sniff_target, args = (q,))
	sniffer.daemon = True
	sniffer.start()
	while (not m_finished):
		try:
			pkt = q.get(timeout = 1)
			sniffProbe(pkt)
		except Empty:
			pass
	
threaded_sniff()	
	
#old way
#sniff(iface=interface, lfilter = lambda x: (x.haslayer(Dot11ProbeReq)), prn=sniffProbe)

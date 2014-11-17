from scapy.all import *
from datetime import datetime, timedelta

interface = 'wlan0'
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
        	
#def sniffLog():
	#read and write log data from the sniffing
#def whitelist():
	#provide the capability to whitelist addresses from alerter
#def alerter():
	#provide a method to alert of a newly detected wifi with a dwell time exceeding the max
#measure signal strength
	#how to get the signal strength out of the packet?
#manage the lists of unknown addresses
	#associated with a home address?
#channel hopping code

#def display a list of the dwelling macs
	#time now - time last seen (filter after x time)




sniff(iface=interface, lfilter = lambda x: (x.haslayer(Dot11ProbeReq)), prn=sniffProbe)

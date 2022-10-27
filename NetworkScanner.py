#!/usr/bin/env python3

import sys
import scapy.all as scapy
import optparse

def ipParser():
	parser = optparse.OptionParser()
	parser.add_option("-i", "--ip", help="Specify Ip address", dest="ip")
	options, arguements = parser.parse_args()
	#verification
	if not options.ip:
		raise Exception("Ip address no found. use --help for more information")
		sys.exit()
	return options



def networkScanner(ip):
	arpRequest=scapy.ARP()
	arpRequest.pdst=ip
	broadcastMac=scapy.Ether()
	broadcastMac.dst="ff:ff:ff:ff:ff:ff"
	arpPacket=broadcastMac/arpRequest
	#print(arpPacket.summary())
	#arpPacket.show()
	#print(arpRequest.summary())
	#scapy.ls(scapy.srp(arpPacket))
	successful = scapy.srp(arpPacket, timeout=1, verbose=False)[0]
	return successful



def printOutput(successful):
	print("Ip\t\t\t\t\t\tMac")
	print("----------------------------------------------------------")
	for p in successful:
		print(p[1].psrc+"\t\t\t\t"+p[1].hwsrc+"\n\n")






options = ipParser()

successful = networkScanner(options.ip)

printOutput(successful)

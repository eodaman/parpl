from scapy.all import *
import signal
import sys
from datetime import datetime, timedelta

'''
#For better argument parsing. WIP
import argparse

parser = argparse.ArgumentParser(description="Passive ARP learning tool.\nLearn MACs for IP addresses without sending ARP requests, by simply sniffing ARP frames for their sender IPs and MACs.")
parser.add_argument('-f','--filename', type=str,
                    help='Base filename for output files. Default:none')
parser.add_argument('-i','--interface', type=str,
                    help='Network interface to be used. Default:all')

'''


print()
print("Sniffing ARP packets for passive learning of MAC-IP pairs\nPress Ctrl+C to end")
do_save_results = False
try:
	filename_base = sys.argv[1]

	filename_arp_add = filename_base + "_arp_add.sh"
	filename_arp_del = filename_base + "_arp_del.sh"
	filename_raw     = filename_base + "_raw.txt"
	filename_ip_list = filename_base + "_ip_list.txt"

	do_save_results = True
	print("Will save final results and scripts at", filename_arp_add, filename_arp_del, filename_raw, filename_ip_list)
except:
	print("No filename provided, will not save results")

try:
	sniff_iface = sys.argv[2]
	print("Sniffing on interface ", sniff_iface)
except:
	print("Sniffing on all interfaces")


arpdict = dict()

def prn2(packet):
	if packet.haslayer(ARP):
		print(packet.psrc, " is at ", packet.hwsrc)
		
		try:
			if (packet.hwsrc != arpdict[packet.psrc]):
				print("MAC Address changed for IP", packet.psrc, "from", arpdict[packet.psrc], "to", packet.hwsrc, "at", datetime.now())
				print("Most recent version will be saved!")
		except:
			pass
		arpdict[packet.psrc] = packet.hwsrc 


def save_results(timestop,duration):
	

	
	arp_add_file		= open(filename_arp_add, "w")
	arp_del_file		= open(filename_arp_del, "w")
	raw_results_file	= open(filename_raw, "w")
	ip_list_file		= open(filename_ip_list,"w")
	
	arp_add_file.write("#!/bin/bash\n")
	arp_del_file.write("#!/bin/bash\n")
	
	raw_results_file.write(str(filename_raw+"\n" ))
	raw_results_file.write(str("ARP learning results between "+ str(timestart) + " and "+ str(timestop)+"\n" ))
	raw_results_file.write(str("Duration: " + str(duration)+"\n" ))
	
	for pair in arpdict.items():
		arp_add_file.write(str("arp -s " + str(pair[0]) + " " + str(pair[1])+"\n" ))
		arp_del_file.write(str("arp -d " + str(pair[0])+"\n" ))
		raw_results_file.write(str(str(pair[0]) + " has MAC address: " + str(pair[1])+"\n" ))
		ip_list_file.write(str(pair[0])+"\n")
		
	arp_add_file.close()
	arp_del_file.close()
	raw_results_file.close()
	ip_list_file.close()

	print("Saved final results and scripts at", filename_arp_add, filename_arp_del, filename_raw, filename_ip_list)	
		
def signal_handler(sig, frame):
	print()
	timestop = datetime.now()
	duration = timestop - timestart
	print("Sniffing stopped at ",timestop)
	print("Duration: ", duration)
	if do_save_results:
		save_results(timestop, duration)
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
timestart = datetime.now()
print()
print("Sniffing started at", timestart)
if sniff_iface:
	sniff(iface=sniff_iface, store=False, prn=prn2)
else:
	sniff(store=False, prn=prn2)






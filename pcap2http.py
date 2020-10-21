from scapy.all import *
import re,argparse,sys,os
parser = argparse.ArgumentParser(description="[+] PCAP2HTTP Extractor [+]")
parser.add_argument('-p', required=True, default=None, help='Add the PCAP file')
parser.add_argument('-m', required=True, default=None, help='Add the HTTP method [ex: POST|GET|PUT|etc..]')
args = vars(parser.parse_args())
if os.path.isfile(args['p']):
	packets = rdpcap(args['p'])
	sessions = packets.sessions()
	for session in sessions:
		for packet in sessions[session]:
			if packet.haslayer(TCP):
				payload = bytes(packet[TCP].payload)
				if args['m'].upper() in payload: # you can change the http method if you want
					print(payload)
else:
	print("[-] PCAP File Not found [-]")

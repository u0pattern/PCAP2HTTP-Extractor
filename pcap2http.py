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
				if packet[TCP].dport == 80 or packet[TCP].dport == 443:
					payload = bytes(packet[TCP].payload)
					if args['m'] in payload: # you can change the http method if you want
						print("http[s]://"+payload.split('Host: ')[1].split("\r\n")[0]+payload.split(args['m']+' ')[1].split(' HTTP/1.1')[0])
else:
	print("[-] PCAP File Not found [-]")

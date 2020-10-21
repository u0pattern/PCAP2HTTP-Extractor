# PCAP2HTTP-Extractor
PCAP2HTTP Extractor is a tool that helps to dump all HTTP[s] packets from PCAP file

# Requirements
install scapy: 
`pip install scapy`

# Usage
```
~$ ./pcap2http.py -p [PCAP File] -m [HTTP Method (ex: POST|GET|PUT|etc..)]
~$ ./pcap2http.py -p example.pcap -m GET

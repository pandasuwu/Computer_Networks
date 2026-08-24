# Challenge 01 — The Missing Host

A small laboratory network experienced intermittent connectivity problems.
A packet capture was taken from the LAN while the problem was occurring.

Several hosts were communicating normally, but one machine appears to be
looking for a host that does not respond.

Analyse the PCAP and answer:

1. How many packets does the pcap file capture?
2. What protocols are present in the pcap file?
3. What is the IPv4 address of the default gateway?
4. What is the MAC address associated with the default gateway?
5. How many unique IPv4 source addresses occur in the capture?
6. Which IPv4 address received ARP requests but never sent an ARP reply?
7. How many unanswered ARP requests were observed?

Your program must accept a PCAP file and parse packets directly. 
Wireshark/tshark should not be used as the analysis engine.

BASIC NETWORK SNIFFER(CYBER SECURITY):
This repository hosts a basic Python network packet sniffer, 
packet_sniffer.py built with the Scapy library. It's designed to capture, dissect, and analyze real-time network traffic, providing insights into common protocols and packet structures. The project highlights hands-on experience with low-level network operations, protocol analysis (Ethernet, IP, TCP, UDP, ICMP), and problem-solving in a Windows environment.


Technologies Used:

1.)Python 

2.)Scapy (for packet manipulation and sniffing) 

3.)Npcap (packet capture driver for Windows) 

4.)Operating System: Developed and tested on Windows 10/11 



Features:

-Real-time Packet Capture: Utilizes Scapy's sniff() function to listen for network traffic on a specified interface. 

-Layer-by-Layer Dissection: Processes each captured packet, dissecting it layer by layer (Ethernet, IP, TCP, UDP, ICMP) to extract relevant information. 

-Detailed Information Display: Outputs key packet details including:

1.)Source and Destination MAC Addresses 

2.)Source and Destination IP Addresses 

3.)Protocol (e.g., TCP, UDP, ICMP) 

4.)Source and Destination Ports (for TCP/UDP) 

5.)TCP Flags (SYN, ACK, FIN, etc.) 

6.)Raw Payload Data 

-Human-Readable Protocol Names: Helper functions (get_protocol_name, get_icmp_type_name) translate numerical codes into clear, human-readable names for enhanced output clarity. 

-Robust Error Handling: Includes basic error handling for common issues like missing Scapy, permission denied, and incorrect interface names. 

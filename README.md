BASIC NETWORK SNIFFER(CYBER SECURITY):
This repository hosts a basic Python network packet sniffer, 
packet_sniffer.py built with the Scapy library. It's designed to capture, dissect, and analyze real-time network traffic, providing insights into common protocols and packet structures. The project highlights hands-on experience with low-level network operations, protocol analysis (Ethernet, IP, TCP, UDP, ICMP), and problem-solving in a Windows environment.

How to run:
1.) Clone the repository
2.) Install Scapy
3.) Install Npcap (Windows Only)
4.) Identify your Network Interface:
-Open a Python interpreter as Administrator and run scapy.all.show_interfaces().
-Alternatively, use netsh wlan show interfaces (Wi-Fi) or netsh lan show interfaces (Ethernet) in an Administrator Command Prompt to find your active adapter's GUID.
5.) Update INTERFACE variable: In packet_sniffer.py, replace {YOUR-ACTUAL-GUID-HERE} with your identified interface name or GUID.
6.) Run the script (as Administrator) on command prompt

Technologies Used:

1.)Python 

2.)Scapy (for packet manipulation and sniffing) 

3.)Npcap (packet capture driver for Windows) 

4.)Operating System: Developed and tested on Windows 10/11 

FEATURES:

-Real-time Packet Capture: Utilizes Scapy's sniff() function to listen for network traffic on a specified interface. 

-Layer-by-Layer Dissection: Processes each captured packet, dissecting it layer by layer (Ethernet, IP, TCP, UDP, ICMP) to extract relevant information. 

-Outputs key packet details includes:- [Source and Destination MAC Addresses, Source and Destination IP Addresses, Protocol (e.g., TCP, UDP, ICMP), Source and Destination Ports (for TCP/UDP), TCP Flags (SYN, ACK, FIN, etc.), Raw Payload Data] 

-Human-Readable Protocol Names: Helper functions (get_protocol_name, get_icmp_type_name) translate numerical codes into clear, human-readable names for enhanced output clarity. 

-Robust Error Handling: Includes basic error handling for common issues like missing Scapy, permission denied, and incorrect interface names. 

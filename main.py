# main.py -- put your code here!

import ubinascii

print("\nBeginning of pcap parsing...\n")
reader = open("ipv6udp_packet.pcap")
packet = reader.read()
packetHexa = ubinascii.hexlify(packet)
packetHexaContent = packetHexa[80:]
print("Trame content (hexa): %s" % packetHexaContent)

IP_version = packetHexaContent[0:1]
print("\tIP version (decimal): %d" % int(IP_version, 16))

IP_TrafficClass = packetHexaContent[1:3]
print("\tIP Traffic Class (hexa): %s" % IP_TrafficClass)

IP_FlowLabel = packetHexaContent[3:8]
print("\tIP Flow Label (hexa): %s" % IP_FlowLabel)

IP_PayloadLength = packetHexaContent[8:12]
print("\tIP Payload Length (decimal): %d" % int(IP_PayloadLength, 16))

IP_NextHeader = packetHexaContent[12:14]
print("\tIP Next Header (decimal): %d" % int(IP_NextHeader, 16))

IP_HopLimit = packetHexaContent[14:16]
print("\tIP Hop Limit (decimal): %d" % int(IP_HopLimit, 16))

IP_SourceAddress = packetHexaContent[16:48]
print("\tIP Source Address (hexa): %s" % IP_SourceAddress)

IP_DestinationAddress = packetHexaContent[48:80]
print("\tIP Destination Address (hexa): %s" % IP_DestinationAddress)

UDP_SourcePort = packetHexaContent[80:84]
print("\tUDP Source Port (decimal): %d" % int(UDP_SourcePort, 16))

UDP_DestinationPort = packetHexaContent[84:88]
print("\tUDP Destination Port (decimal): %d" % int(UDP_DestinationPort, 16))

UDP_Length = packetHexaContent[88:92]
print("\tUDP Length (decimal): %d" % int(UDP_Length, 16))

UDP_Checksum = packetHexaContent[92:96]
print("\tUDP Checksum (hexa): %s" % UDP_Checksum)

CoAP_version = packetHexaContent[96:97]
CoAP_version_bin = bin(int(CoAP_version, 16))[2:3]
print("\tCoAP version (decimal): %d" % int(CoAP_version_bin, 2))

CoAP_Type = packetHexaContent[96:97]
CoAP_Type_bin = bin(int(CoAP_version, 16))[3:5]
print("\tCoAP Type (decimal): %d" % int(CoAP_Type_bin, 2))

CoAP_TokenLength = packetHexaContent[97:98]
print("\tCoAP Token Length (decimal): %d" % int(CoAP_TokenLength, 16))

CoAP_Code = packetHexaContent[98:100]
print("\tCoAP Code (decimal): %d" % int(CoAP_Code, 16))

CoAP_MessageID = packetHexaContent[100:104]
print("\tCoAP MessageID (decimal): %d" % int(CoAP_MessageID, 16))

import ubinascii

class Parser:
    
    def __init__(self, pcap_file_name):
        self.pcap_file_name = pcap_file_name
        self.IPv6_header_fields = {}
        self.UDP_header_fields = {}
        self.CoAP_header_fields = {}
    
    def parser(self):

        print("\nBeginning of pcap parsing...\n")
        self.reader = open(self.pcap_file_name)
        self.packet = self.reader.read()
        self.packetHexa = ubinascii.hexlify(self.packet)
        self.sepacketHexaContent = self.packetHexa[80:]
        print("Trame content (hexa): %s" % self.sepacketHexaContent)

        self.IPv6_header_fields["IP_version"] = self.sepacketHexaContent[0:1]
        print("\tIP version (decimal): %d" % int(self.IPv6_header_fields["IP_version"], 16))

        self.IPv6_header_fields["IP_trafficClass"] = self.sepacketHexaContent[1:3]
        print("\tIP Traffic Class (hexa): %s" % self.IPv6_header_fields["IP_trafficClass"])

        self.IPv6_header_fields["IP_flowLabel"] = self.sepacketHexaContent[3:8]
        print("\tIP Flow Label (hexa): %s" % self.IPv6_header_fields["IP_flowLabel"])

        self.IPv6_header_fields["IP_payloadLength"] = self.sepacketHexaContent[8:12]
        print("\tIP Payload Length (decimal): %d" % int(self.IPv6_header_fields["IP_payloadLength"], 16))

        self.IPv6_header_fields["IP_nextHeader"] = self.sepacketHexaContent[12:14]
        print("\tIP Next Header (decimal): %d" % int(self.IPv6_header_fields["IP_nextHeader"], 16))

        self.IPv6_header_fields["IP_hopLimit"] = self.sepacketHexaContent[14:16]
        print("\tIP Hop Limit (decimal): %d" % int(self.IPv6_header_fields["IP_hopLimit"], 16))

        self.IPv6_header_fields["IP_sourceAddress"] = self.sepacketHexaContent[16:48]
        print("\tIP Source Address (hexa): %s" % self.IPv6_header_fields["IP_sourceAddress"])

        self.IPv6_header_fields["IP_destinationAddress"] = self.sepacketHexaContent[48:80]
        print("\tIP Destination Address (hexa): %s" % self.IPv6_header_fields["IP_destinationAddress"])

        self.UDP_header_fields["UDP_sourcePort"] = self.sepacketHexaContent[80:84]
        print("\tUDP Source Port (decimal): %d" % int(self.UDP_header_fields["UDP_sourcePort"], 16))

        self.UDP_header_fields["UDP_destinationPort"] = self.sepacketHexaContent[84:88]
        print("\tUDP Destination Port (decimal): %d" % int(self.UDP_header_fields["UDP_destinationPort"], 16))

        self.UDP_header_fields["UDP_length"] = self.sepacketHexaContent[88:92]
        print("\tUDP Length (decimal): %d" % int(self.UDP_header_fields["UDP_length"], 16))

        self.UDP_header_fields["UDP_checksum"] = self.sepacketHexaContent[92:96]
        print("\tUDP Checksum (hexa): %s" % self.UDP_header_fields["UDP_checksum"])

        self.CoAP_header_fields["CoAP_version"] = self.sepacketHexaContent[96:97]
        self.CoAP_header_fields["CoAP_version_bin"] = bin(int(self.CoAP_header_fields["CoAP_version"], 16))[2:3]
        print("\tCoAP version (decimal): %d" % int(self.CoAP_header_fields["CoAP_version_bin"], 2))

        self.CoAP_header_fields["CoAP_type"] = self.sepacketHexaContent[96:97]
        self.CoAP_header_fields["CoAP_type_bin"] = bin(int(self.CoAP_header_fields["CoAP_type"], 16))[3:5]
        print("\tCoAP Type (decimal): %d" % int(self.CoAP_header_fields["CoAP_type_bin"], 2))

        self.CoAP_header_fields["CoAP_tokenLength"] = self.sepacketHexaContent[97:98]
        print("\tCoAP Token Length (decimal): %d" % int(self.CoAP_header_fields["CoAP_tokenLength"], 16))

        self.CoAP_header_fields["CoAP_code"] = self.sepacketHexaContent[98:100]
        print("\tCoAP Code (decimal): %d" % int(self.CoAP_header_fields["CoAP_code"], 16))

        self.CoAP_header_fields["CoAP_messageID"] = self.sepacketHexaContent[100:104]
        print("\tCoAP MessageID (decimal): %d" % int(self.CoAP_header_fields["CoAP_messageID"], 16))

    def get_IPv6_header_fields(self):
        return self.IPv6_header_fields

    def get_UDP_header_fields(self):
        return self.UDP_header_fields

    def get_CoAP_header_fields(self):
        return self.CoAP_header_fields
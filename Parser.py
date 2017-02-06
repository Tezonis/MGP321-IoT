import binascii

class Parser:
    
    def __init__(self, pcap_file_name):
        self.pcap_file_name = pcap_file_name
        self.header_fields = {}
    
    def parser(self):

        self.reader = open(self.pcap_file_name, mode="rb")
        self.packet = self.reader.read()
        self.packetHexa = binascii.hexlify(self.packet)
        self.sepacketHexaContent = self.packetHexa[80:]
        print("\n\t\tTrame content (hexa): %s" % self.sepacketHexaContent)

        self.header_fields["IP_version"] = self.sepacketHexaContent[0:1]
        print("\n\t\t\tIP version (decimal): %d" % int(self.header_fields["IP_version"], 16))

        self.header_fields["IP_trafficClass"] = self.sepacketHexaContent[1:3]
        print("\t\t\tIP Traffic Class (hexa): %s" % self.header_fields["IP_trafficClass"])

        self.header_fields["IP_flowLabel"] = self.sepacketHexaContent[3:8]
        print("\t\t\tIP Flow Label (hexa): %s" % self.header_fields["IP_flowLabel"])

        self.header_fields["IP_payloadLength"] = self.sepacketHexaContent[8:12]
        print("\t\t\tIP Payload Length (decimal): %d" % int(self.header_fields["IP_payloadLength"], 16))

        self.header_fields["IP_nextHeader"] = self.sepacketHexaContent[12:14]
        print("\t\t\tIP Next Header (decimal): %d" % int(self.header_fields["IP_nextHeader"], 16))

        self.header_fields["IP_hopLimit"] = self.sepacketHexaContent[14:16]
        print("\t\t\tIP Hop Limit (decimal): %d" % int(self.header_fields["IP_hopLimit"], 16))

        self.header_fields["IP_sourceAddress"] = self.sepacketHexaContent[16:48]
        print("\t\t\tIP Source Address (hexa): %s" % self.header_fields["IP_sourceAddress"])

        self.header_fields["IP_destinationAddress"] = self.sepacketHexaContent[48:80]
        print("\t\t\tIP Destination Address (hexa): %s" % self.header_fields["IP_destinationAddress"])

        self.header_fields["UDP_sourcePort"] = self.sepacketHexaContent[80:84]
        print("\t\t\tUDP Source Port (decimal): %d" % int(self.header_fields["UDP_sourcePort"], 16))

        self.header_fields["UDP_destinationPort"] = self.sepacketHexaContent[84:88]
        print("\t\t\tUDP Destination Port (decimal): %d" % int(self.header_fields["UDP_destinationPort"], 16))

        self.header_fields["UDP_length"] = self.sepacketHexaContent[88:92]
        print("\t\t\tUDP Length (decimal): %d" % int(self.header_fields["UDP_length"], 16))

        self.header_fields["UDP_checksum"] = self.sepacketHexaContent[92:96]
        print("\t\t\tUDP Checksum (hexa): %s" % self.header_fields["UDP_checksum"])

        self.header_fields["CoAP_version"] = self.sepacketHexaContent[96:97]
        self.header_fields["CoAP_version_bin"] = bin(int(self.header_fields["CoAP_version"], 16))[2:3]
        print("\t\t\tCoAP version (decimal): %d" % int(self.header_fields["CoAP_version_bin"], 2))

        self.header_fields["CoAP_type"] = self.sepacketHexaContent[96:97]
        self.header_fields["CoAP_type_bin"] = bin(int(self.header_fields["CoAP_type"], 16))[3:5]
        print("\t\t\tCoAP Type (decimal): %d" % int(self.header_fields["CoAP_type_bin"], 2))

        self.header_fields["CoAP_tokenLength"] = self.sepacketHexaContent[97:98]
        print("\t\t\tCoAP Token Length (decimal): %d" % int(self.header_fields["CoAP_tokenLength"], 16))

        self.header_fields["CoAP_code"] = self.sepacketHexaContent[98:100]
        print("\t\t\tCoAP Code (decimal): %d" % int(self.header_fields["CoAP_code"], 16))

        self.header_fields["CoAP_messageID"] = self.sepacketHexaContent[100:104]
        print("\t\t\tCoAP MessageID (decimal): %d" % int(self.header_fields["CoAP_messageID"], 16))

    def get_header_fields(self):
        return self.header_fields

class EndSystem:
    
    def __init__(self):
    	self.pcap_file_name = "ipv6udp_packet.pcap"
        self.context = []

    def addRule(self, rule):
    	self.context.append(rule)

    def getPacket(self):
    	return self.pcap_file_name
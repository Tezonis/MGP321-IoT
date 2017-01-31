class Compressor:
    
    def __init__(self):
        self.context = []

    def addRule(self, rule):
    	self.context.append(rule)

    def receivePacket(self, received_IPv6_header_fields, received_UDP_header_fields, received_CoAP_header_fields):
    	self.received_IPv6_header_fields = received_IPv6_header_fields
    	self.received_UDP_header_fields = received_UDP_header_fields
    	self.received_CoAP_header_fields = received_CoAP_header_fields

    def printContext(self):
    	i = 0
    	for rule in self.context:
    		print("rule %d :" % i)
    		i += 1
    		for field_name, field_content in rule.items():
    			print("\tfield %s :" % field_name)
    			for field_desc_name, field_desc_content in field_content.items():
    				print("\t\t %s : %s" % (field_desc_name, field_desc_content))

    def printReceivedPacket(self):
    	for field_name, field_content in self.received_IPv6_header_fields.items():
    		print("%s : %s" % (field_name, field_content))
    	for field_name, field_content in self.received_UDP_header_fields.items():
    		print("%s : %s" % (field_name, field_content))
    	for field_name, field_content in self.received_CoAP_header_fields.items():
    		print("%s : %s" % (field_name, field_content))
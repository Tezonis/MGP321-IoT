import ure
import ubinascii

class Compressor:

    field_size = {
            "IP_version": 4,
            "IP_trafficClass": 8,
            "IP_flowLabel": 20,
            "IP_payloadLength": 16,
            "IP_nextHeader": 8,
            "IP_hopLimit": 8,
            "IP_sourceAddress": 64,
            "IP_destinationAddress": 64,
            "UDP_sourcePort": 16,
            "UDP_destinationPort": 16,
            "UDP_length": 16,
            "UDP_checksum": 16,
            "CoAP_version": 2,
            "CoAP_type": 2,
            "CoAP_tokenLength": 4,
            "CoAP_code": 8,
            "CoAP_messageID": 16
        }
    
    def __init__(self):
        self.context = []

    def addRule(self, rule):
    	self.context.append(rule)

    def receivePacket(self, received_header_fields):
    	self.received_header_fields = received_header_fields

    def analyzeReceivedPacket(self):
    	rule_found = False
    	rule_found_number = 0
    	i = 0
    	for rule in self.context:
    		print("\nAnalyzing rule %d..." % i)
    		matched = False
    		for field_name, field_content in rule.items():
    			print("\tfield %s :" % field_name)
    			if field_content["matchingOperator"]=="equal":
    				print("\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields[field_name]))
    				if field_content["targetValue"]==self.received_header_fields[field_name]:
    					print("\t\t\t...it is a match.")
    					matched = True
    				else:
    					matched = False
    					break
    			if field_content["matchingOperator"]=="ignore":
    				print("\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields[field_name]))
    				print("\t\t\t...but they are ignored.")
    				matched = True
    			reg = ure.search('MSB\((.*)\)', field_content["matchingOperator"])
    			if reg:
    				msb = int(reg.group(1))
    				print("\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields[field_name]))

    				ctx_bin = bin(int(field_content["targetValue"], 16))[2:]
    				rcv_bin = bin(int(self.received_header_fields[field_name], 16))[2:]

    				ctx_nbz = self.field_size[field_name] - len(ctx_bin)
    				ctx_bin = self.zfill(ctx_bin, ctx_nbz)

    				rcv_nbz = self.field_size[field_name] - len(rcv_bin)
    				rcv_bin = self.zfill(rcv_bin, rcv_nbz)

    				if ctx_bin[0:msb]==rcv_bin[0:msb]:
    					print("\t\t\t...it is a match on the first %d bits." % msb)
    					matched = True
    				else:
    					matched = False
    					break
    		if matched:
    			print("Rule %d matches." % i)
    			rule_found = True
    			rule_found_number = i
    			break
    		else:
    			print("Rule %d do not match." % i)
    		i += 1

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
    	for field_name, field_content in self.received_header_fields.items():
    		print("%s : %s" % (field_name, field_content))

    def zfill(self, strtofill, nbz):
    	filledstr = strtofill
    	for i in range(nbz):
    		filledstr = "0" + filledstr
    	return filledstr

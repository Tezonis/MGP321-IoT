import re
import binascii

class Compressor:
    
    def __init__(self):
        self.context = []
        self.received_header_fields_from_ES = {}
        self.received_compressed_packet = {}
        self.compressed_packet_to_send = {}
        self.decompressed_packet = {
            "IP_version": "",
            "IP_trafficClass": "",
            "IP_flowLabel": "",
            "IP_payloadLength": "",
            "IP_nextHeader": "",
            "IP_hopLimit": "",
            "IP_sourceAddress": "",
            "IP_destinationAddress": "",
            "UDP_sourcePort": "",
            "UDP_destinationPort": "",
            "UDP_length": "",
            "UDP_checksum": "",
            "CoAP_version": "",
            "CoAP_type": "",
            "CoAP_tokenLength": "",
            "CoAP_code": "",
            "CoAP_messageID": ""
        }
        self.field_size = {
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

    def addRule(self, rule):
        self.context.append(rule)

    def receivePacketFromES(self, received_header_fields_from_ES):
        self.received_header_fields_from_ES = received_header_fields_from_ES

    def analyzeReceivedPacketFromES(self):
        self.rule_found = False
        self.rule_found_id = 0
        i = 0
        for rule in self.context:
            print("\n\t\tAnalyzing rule %d..." % i)
            matched = False
            for field_name, field_content in rule.items():
                print("\t\t\tfield %s :" % field_name)
                if field_content["matchingOperator"]=="equal":
                    print("\t\t\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields_from_ES[field_name]))
                    if field_content["targetValue"]==self.received_header_fields_from_ES[field_name]:
                        print("\t\t\t\t\t...it is a match.")
                        matched = True
                    else:
                        matched = False
                        break
                if field_content["matchingOperator"]=="ignore":
                    print("\t\t\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields_from_ES[field_name]))
                    print("\t\t\t\t\t...but they are ignored.")
                    matched = True
                reg = re.search('MSB\((.*)\)', field_content["matchingOperator"])
                if reg:
                    msb = int(reg.group(1))
                    print("\t\t\t\t%s context value is %s and received value is %s..." % (field_name, field_content["targetValue"], self.received_header_fields_from_ES[field_name]))

                    ctx_bin = bin(int(field_content["targetValue"], 16))[2:]
                    rcv_bin = bin(int(self.received_header_fields_from_ES[field_name], 16))[2:]

                    ctx_nbz = self.field_size[field_name] - len(ctx_bin)
                    ctx_bin = self.zfill(ctx_bin, ctx_nbz)

                    rcv_nbz = self.field_size[field_name] - len(rcv_bin)
                    rcv_bin = self.zfill(rcv_bin, rcv_nbz)

                    if ctx_bin[0:msb]==rcv_bin[0:msb]:
                        print("\t\t\t\t\t...it is a match on the first %d bits." % msb)
                        matched = True
                    else:
                        matched = False
                        break
            if matched:
                print("\t\tRule %d matches." % i)
                self.rule_found = True
                self.rule_found_id = i
                break
            else:
                print("\t\tRule %d do not match." % i)
            i += 1

    def compressPacket(self):
        if self.rule_found:
            print("\n\t\tStart compressing packet with the rule %d...\n" % self.rule_found_id)
            for field_name, field_content in self.context[self.rule_found_id].items():
                print("\t\t\tfield %s :" % field_name)
                reg = re.search('LSB\((.*)\)', field_content["compDecompFct"])
                if reg:
                    lsb = int(reg.group(1))
                    rcv_bin = bin(int(self.received_header_fields_from_ES[field_name], 16))[2:]
                    rcv_nbz = self.field_size[field_name] - len(rcv_bin)
                    rcv_bin = self.zfill(rcv_bin, rcv_nbz)
                    self.compressed_packet_to_send[field_name] = rcv_bin[self.field_size[field_name]-lsb:self.field_size[field_name]]
                    print("\t\t\t\t%d lsb of %s are sent to the server, value is %s" % (lsb, field_name, self.compressed_packet_to_send[field_name]))
                    tmp = int(self.compressed_packet_to_send[field_name], 2)
                    self.compressed_packet_to_send[field_name] = binascii.hexlify(tmp.to_bytes((tmp.bit_length() + 7) // 8, byteorder="big"))
                elif field_content["compDecompFct"]=="value-sent":
                    self.compressed_packet_to_send[field_name] = self.received_header_fields_from_ES[field_name]
                    print("\t\t\t\tfield content of %s is sent to the server, value is %s" % (field_name, self.compressed_packet_to_send[field_name]))
                else:
                    print("\t\t\t\tfield elided.")
            self.compressed_packet_to_send["rule"] = self.rule_found_id
                    
        else:
            print("\t\tNo rule found, the packet is dropped.")

    def sendPacketToLA(self):
        return self.compressed_packet_to_send

    def receiveCompressedPacket(self, received_compressed_packet):
        self.received_compressed_packet = received_compressed_packet

    def decompressPacket(self):
        print("\n\t\tStart decompressing packet with the rule %d...\n" % self.received_compressed_packet["rule"])
        for field_name, field_content in self.decompressed_packet.items():
            print("\t\t\tfield %s :" % field_name)
            if self.context[self.received_compressed_packet["rule"]][field_name]["compDecompFct"]=="not-sent":
                self.decompressed_packet[field_name] = self.context[self.received_compressed_packet["rule"]][field_name]["targetValue"]
                print("\t\t\t\tdecompressed %s is %s (retrieved from the context)" % (field_name, self.decompressed_packet[field_name]))

            if self.context[self.received_compressed_packet["rule"]][field_name]["compDecompFct"]=="value-sent":
                self.decompressed_packet[field_name] = self.received_compressed_packet[field_name]
                print("\t\t\t\tdecompressed %s is %s (retrieved from the link)" % (field_name, self.decompressed_packet[field_name]))

            reg = re.search('LSB\((.*)\)', self.context[self.received_compressed_packet["rule"]][field_name]["compDecompFct"])
            if reg:
                lsb = int(reg.group(1))
                ctx_bin = int(self.context[self.received_compressed_packet["rule"]][field_name]["targetValue"], 16)
                rcv_bin = int(self.received_compressed_packet[field_name], 16)
                res_or = ctx_bin | rcv_bin
                res_or = binascii.hexlify(res_or.to_bytes((res_or.bit_length() + 7) // 8, byteorder="big"))
                self.decompressed_packet[field_name] = res_or
                msb = self.field_size[field_name] - lsb
                print("\t\t\t\tdecompressed %s is %s (retrieved from the context (%d MSB) and from the link (%d LSB))" % (field_name, self.decompressed_packet[field_name], msb, lsb))

    def sendDecompressedPacketToLA(self):
        return self.decompressed_packet

    def printContext(self):
        i = 0
        for rule in self.context:
            print("\t\trule %d :" % i)
            i += 1
            for field_name, field_content in rule.items():
                print("\t\t\tfield %s :" % field_name)
                for field_desc_name, field_desc_content in field_content.items():
                    print("\t\t\t\t %s : %s" % (field_desc_name, field_desc_content))

    def printReceivedPacket(self):
        for field_name, field_content in self.received_header_fields_from_ES.items():
            print("\t\t\t%s : %s" % (field_name, field_content))

    def printSentPacket(self):
        for field_name, field_content in self.compressed_packet_to_send.items():
            print("\t\t\t%s : %s" % (field_name, field_content))

    def zfill(self, strtofill, nbz):
        filledstr = strtofill
        for i in range(nbz):
            filledstr = "0" + filledstr
        return filledstr

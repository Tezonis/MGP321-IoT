# main.py -- put your code here!

import Parser
import EndSystem
import ApplicationServer
import Compressor

endSystemA = EndSystem.EndSystem()
compressorA = Compressor.Compressor()
compressorB = Compressor.Compressor()
applicationServerB = ApplicationServer.ApplicationServer()

rule1 = {
			"IP_version": {
				"targetValue": 0x6,
				"matchingOperator": "equal",
				"compDecompFct": "sent"
				},
			"IP_trafficClass": {
				"targetValue": 0x00,
				"matchingOperator": "ignore",
				"compDecompFct": "not-sent"
				}
		}

endSystemA.addRule(rule1)
compressorA.addRule(rule1)

parser = Parser.Parser(endSystemA.getPacket())
parser.parser()
compressorA.receivePacket(parser.get_IPv6_header_fields(), parser.get_UDP_header_fields(), parser.get_CoAP_header_fields())
print("\ncompressorA context is :")
compressorA.printContext()
print("\ncompressorA receivedPacket is :")
compressorA.printReceivedPacket()
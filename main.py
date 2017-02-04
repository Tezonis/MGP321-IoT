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
				"targetValue": b"6",
				"matchingOperator": "equal",
				"compDecompFct": "not-sent"
				},
			"IP_trafficClass": {
				"targetValue": b"00",
				"matchingOperator": "ignore",
				"compDecompFct": "not-sent"
				},
			"IP_flowLabel": {
				"targetValue": b"51f00",
				"matchingOperator": "MSB(16)",
				"compDecompFct": "LSB(8)"
				}
		}

rule2 = {
			"IP_version": {
				"targetValue": b"6",
				"matchingOperator": "equal",
				"compDecompFct": "value-sent"
				},
			"IP_trafficClass": {
				"targetValue": b"00",
				"matchingOperator": "ignore",
				"compDecompFct": "not-sent"
				},
			"UDP_destinationPort": {
				"targetValue": b"1600",
				"matchingOperator": "MSB(8)",
				"compDecompFct": "LSB(8)"
				}
		}

endSystemA.addRule(rule1)
compressorA.addRule(rule1)
endSystemA.addRule(rule2)
compressorA.addRule(rule2)

parser = Parser.Parser(endSystemA.getPacket())
parser.parser()
compressorA.receivePacket(parser.get_header_fields())
print("\ncompressorA context is :")
compressorA.printContext()
print("\ncompressorA receivedPacket is :")
compressorA.printReceivedPacket()
compressorA.analyzeReceivedPacket()
compressorA.compressPacket()
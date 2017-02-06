# main.py -- put your code here!

import Parser
import EndSystem
import ApplicationServer
import Compressor

### Elements instantiation ###

print("\n### Elements instantiation ###")

endSystemA = EndSystem.EndSystem()
print("\n\t End System (ES) A instantiated.")
compressorA = Compressor.Compressor()
print("\t Compressor (LC) A instantiated.")
compressorB = Compressor.Compressor()
print("\t Compressor (LC) B instantiated.")
applicationServerB = ApplicationServer.ApplicationServer()
print("\t Application Server (LA) B instantiated.")

### Rules creation ###

print("\n### Rules creation ###")

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
            "IP_flowLabel": {
                "targetValue": b"51f36",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "IP_payloadLength": {
                "targetValue": b"000c",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "IP_nextHeader": {
                "targetValue": b"11",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "IP_hopLimit": {
                "targetValue": b"40",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "IP_sourceAddress": {
                "targetValue": b"20010470cc59de300000000000001001",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "IP_destinationAddress": {
                "targetValue": b"200141d00052010000000000000008d4",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "UDP_sourcePort": {
                "targetValue": b"8d8c",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "UDP_destinationPort": {
                "targetValue": b"1600",
                "matchingOperator": "MSB(8)",
                "compDecompFct": "LSB(8)"
                },
            "UDP_length": {
                "targetValue": b"000c",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "UDP_checksum": {
                "targetValue": b"8c63",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "CoAP_version": {
                "targetValue": b"4",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "CoAP_type": {
                "targetValue": b"4",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "CoAP_tokenLength": {
                "targetValue": b"3",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "CoAP_code": {
                "targetValue": b"6f",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                },
            "CoAP_messageID": {
                "targetValue": b"4150",
                "matchingOperator": "ignore",
                "compDecompFct": "not-sent"
                }
        }

endSystemA.addRule(rule1)
compressorA.addRule(rule1)
compressorB.addRule(rule1)
endSystemA.addRule(rule2)
compressorA.addRule(rule2)
compressorB.addRule(rule2)

print("\n\t Rules created.")
print("\t Contexts filled.\n")
compressorA.printContext()
# compressorB.printContext()

### Exchanges ###

print("\n### Exchanges ###")

## Parsing ##
print("\n\t## Beginning of %s parsing ##" % endSystemA.getPacket())
parser = Parser.Parser(endSystemA.getPacket())
parser.parser()

## Sending parsed packet to compressor A ##
print("\n\t## Sending parsed packet to compressor A ##")
compressorA.receivePacketFromES(parser.get_header_fields())
print("\n\t\tParsed packet received by compressor A.\n")
compressorA.printReceivedPacket()

## Search of matching rule in the context ##
print("\n\t## Search of matching rule in the context ##")
compressorA.analyzeReceivedPacketFromES()

## Compression of the packet to send ##
print("\n\t## Compression of the packet to send ##")
compressorA.compressPacket()

## Sending compressed packet to B ##
print("\n\t## Sending compressed packet to B ##")
print("\n\t\tcompressorA compressed packet sent to B.\n")
compressorA.printSentPacket()
compressorB.receiveCompressedPacket(compressorA.sendPacketToLA())

## Decompression of received packet ##
print("\n\t## Decompression of received packet ##")
compressorB.decompressPacket()

## Sending decompressed packet to Application Server B ##
print("\n\t## Sending decompressed packet to Application Server B ##")
applicationServerB.receiveDecompressedPacketFromLC(compressorB.sendDecompressedPacketToLA())
print("\n\t\tDecompressed packet received by Application Server B.\n")
applicationServerB.printReceivedDecompressedPacket()
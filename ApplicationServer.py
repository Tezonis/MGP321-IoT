class ApplicationServer:
    
    def __init__(self):
        self.decompressedPacket = {}

    def receiveDecompressedPacketFromLC(self, decompressedPacket):
        self.decompressedPacket = decompressedPacket

    def printReceivedDecompressedPacket(self):
        for field_name, field_content in self.decompressedPacket.items():
            print("\t\t\t%s : %s" % (field_name, field_content))

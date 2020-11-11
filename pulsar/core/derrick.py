import gzip 


class DerrickPacket:

    def __init__(self, line):
        (self.ntime, self.proto, self.src, self.dst, self.msg) = line.split(" ", 4)
        self.ntime = float(self.ntime)

    def __str__(self):
        return " ".join([str(self.ntime), self.proto, self.src, self.dst, self.msg])

    def concat(self, newPacket):
        assert(self.src == newPacket.src and
               self.dst == newPacket.dst)
#               self.proto == newPacket.proto and
#               self.ntime <= newPacket.ntime
        self.ntime = newPacket.ntime
        self.msg += newPacket.msg


class DerrickReader:

    def __init__(self, derrickFile):
        self.derrickFile = derrickFile
        g = GzipFile(derrickFile, "rb")
        self.messages = [DerrickPacket(l.rstrip("\r\n")) for l in g]
        g.close()

#change to what ever it is
class DerrickWriter:

    def __init__(self, derrickFile):
        self.derrickFile = derrickFile
        print("We are going to file", derrickFile)
    def writePackets(self, messages):
        g = open (self.derrickFile, "w+")
        for m in messages:
            g.write(m.__str__())
            g.write("\n")
        g.close()

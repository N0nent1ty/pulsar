#!/usr/bin/python

import time
import os.path
import os
import configparser
import scapy
from ast import literal_eval

from pulsar.core import sally
from pulsar.core.derrick import DerrickReader, DerrickWriter
from pulsar.core.filter import PacketMerger, ProtocolFilter, ValidSip
from pulsar.core.session import UniversalSessionHandler, SipSessionHandler


PARSER_UNIVERSAL = "universal"
PARSER_SIP = "sip"





class DerrickPacket:
    def __init__(self,packet):
        if packet.haslayer("IP"):
            self.src=packet["IP"].src
            self.dst=packet["IP"].dst
            self.proto="T"
            self.ntime=float(packet["IP"].time)
        if packet.haslayer("TCP"):
            self.msg=packet["TCP"].payload.original.decode(errors="ignore")
            #self.msg=self.msg.decode("ascii", 'ignore')
            #print(self.msg)
        #print(f"packets\n {self.src} {self.dst}")

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

    def __init__(self, pcapFile):
        self.pcapFile = pcapFile
        self.messages =[]
        packets=scapy.all.rdpcap(pcapFile)
        for p in packets:
            self.messages.append(DerrickPacket(p))
        





class Harry():

    def __init__(self, pcapfile, path_conf):

        self.pcap_file = pcapfile
        self.path_conf = path_conf

        # open conf file
        config = configparser.RawConfigParser()
        harry_conf = os.path.join(path_conf, "harry.conf")
        config.readfp(open(harry_conf))

        self.parser = config.get('harry', 'parser')
        self.sally_bin = config.get('harry', 'sally')
        self.step = literal_eval(config.get('harry', 'step'))
        self.ngram = literal_eval(config.get('harry', 'ngram'))
        self.ratio = literal_eval(config.get('harry', 'ratio'))
        self.timeout = literal_eval(config.get('harry', 'timeout'))
        self.validateSip = literal_eval(config.get('harry', 'validateSip'))


    def generate_prisma_input(self,pcap_file):

        (base, _) = os.path.splitext(self.pcap_file)
        #dr = [DerrickPacket(l.rstrip(b"\r\n")) for l in drfile]
        #
        dr = DerrickReader(pcap_file)

        #-------------my-modification---------
        #generate_derrickReaderfromPcap




        if self.parser == PARSER_UNIVERSAL:
            pm = PacketMerger(self.step)
            # filter step:
            filteredMessages = pm.filterMessages(dr.messages)
            # get session information
            sessionHandler = UniversalSessionHandler(filteredMessages,
                                                     self.timeout)
        elif self.parser == PARSER_SIP:
            udpKeeper = ProtocolFilter(["U"])
            if self.validateSip:
                # just keep SIP messages
                udpKeeper.addFilter(ValidSip())
            # filter step:
            filteredMessages = udpKeeper.filterMessages(dr.messages)
            sessionHandler = SipSessionHandler(filteredMessages)
        else:
            raise Exception("Unknown parser type: %s" % self.parser)

        def doSingleWrite(fMessages, theBase):
            dw = DerrickWriter("%s.fdrk" % theBase)
            dw.writePackets(fMessages)
            # write sally information
            sallyInputFile = sally.rawWrite(fMessages, theBase, self.ngram)
            sallyOutputFile = "%s.sally" % theBase
            fsallyOutputFile = "%s.fsally" % theBase
            # process with sally
            sallyCfg = os.path.join(self.path_conf, 'sally.conf')
            os.system("%s -c %s %s %s" % (self.sally_bin, sallyCfg,
                                          sallyInputFile, sallyOutputFile))
            # generate fsally output
            sally.fsallyPreprocessing(sallyOutputFile, fsallyOutputFile)

        if self.ratio < 1.0 and self.ratio > 0.0:
            # do a split in train and test data
            t = time.time()
            isTest = sessionHandler.splitBySession(self.ratio)
            isTrain = [not(test) for test in isTest]
            sessionHandler.writeSessionInformation("%sTrain.harry" % base, isTrain)
            sessionHandler.writeSessionInformation("%sTest.harry" % base, isTest)
            doSingleWrite([f for (w, f) in zip(isTrain, filteredMessages) if w], base + "Train")
            doSingleWrite([f for (w, f) in zip(isTest, filteredMessages) if w], base + "Test")
        else:
            sessionHandler.writeSessionInformation("%s.harry" % base)
            doSingleWrite(filteredMessages, base)

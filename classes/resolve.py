import pyshark
import sys
import os
import time
import cmd
import platform
import multiprocessing
import queue
from mac_vendor_lookup import MacLookup
from collections import defaultdict

class extract:
    #define object
    def __init__(self):
        self.prompt = '=== Welcome to Resolve ==='
        self.pCount = 0
        self.VendorDeviceDict = {'Unknown': {}}
        self.capture = 'mirai-udpflooding-1-dec.pcap'

    #private 
    def __udpCheck(self, srcVendor, packet, srcMac):
        if self.VendorDeviceDict[srcVendor][srcMac]['Rogue'] == False:
            for layer in packet:
                if 'DATA' in str(layer):
                    self.udpCounter = self.udpCounter + 1
                    self.udpTime.append(packet.sniff_time.microsecond)
                    try:
                        self.udpData.add(packet.data.data)
                    except:
                        if self.udpCounter == 10:
                            if len(self.udpData) == 1:
                                self.VendorDeviceDict[srcVendor][srcMac]['Rogue'] = True
                                
                            self.udpTime.sort()
                            maxTime = max(self.udpTime)
                            minTime = min(self.udpTime)
                            rangeTime = maxTime - minTime
                            
                            if rangeTime <= 10:
                                self.VendorDeviceDict[srcVendor][srcMac]['Rogue'] = True

                            self.udpCounter = 0
                            self.udpTime = []
                            self.udpData = set()
                            return
    
    def __getContent(self):
        cap = pyshark.FileCapture(self.capture, display_filter='(tcp or udp) and (not mdns) and (not tls) and (not ssdp) and (not gryphon)')
        srcList = []
        dstList = []
        self.udpCounter = 0
        self.udpData = set()
        self.udpTime = []

        for packet in cap:
            payload = packet
            transportLayer = packet.transport_layer

            if str(packet[0].src) != 'ff:ff:ff:ff:ff:ff' and str(packet[0].dst) != 'ff:ff:ff:ff:ff:ff': 
                if str(packet[0].src) not in srcList:   
                    srcMac = str(packet[0].src)
                    srcList.append(srcMac)
                    devicekey = {srcMac: {'TCP Payload': [], 'TCP Payload Length': [], 'Window Size': [], 'Rogue': False}}

                    try:
                        srcVendor = MacLookup().lookup(srcMac)
                    except:
                        srcVendor = 'Unknown'

                    if srcVendor not in self.VendorDeviceDict:
                        srckey = {srcVendor: {}}
                        self.VendorDeviceDict.update(srckey)
                    if srcMac not in self.VendorDeviceDict[srcVendor]:
                        self.VendorDeviceDict[srcVendor].update(devicekey)

                if packet[0].dst not in dstList:
                    dstMac = str(packet[0].dst)
                    dstList.append(dstMac)
                    devicekey = {dstMac: {'TCP Payload': [], 'TCP Payload Length': [], 'Window Size': [], 'Rogue': False}}

                    try:
                        dstVendor = MacLookup().lookup(dstMac)
                    except:
                        dstVendor = 'Unknown'

                    if dstVendor not in self.VendorDeviceDict:
                        dstkey = {dstVendor: {}}
                        self.VendorDeviceDict.update(dstkey)
                    if dstMac not in self.VendorDeviceDict[dstVendor]:
                        self.VendorDeviceDict[dstVendor].update(devicekey)
                
                if transportLayer == 'TCP':    
                    self.udpCounter = 0
                    self.udpTime = []
                    self.udpData = []
                    try:
                        windowSize = packet[2].window_size_value
                    except:
                        continue
                    self.VendorDeviceDict[srcVendor][srcMac]['Window Size'].append(windowSize)
                    
                    for layer in packet:
                        if 'DATA' in str(layer):
                            try:
                                payload = str(packet.data.data)
                                payloadLen = int(packet.data.len)
                                self.VendorDeviceDict[srcVendor][srcMac]['TCP Payload'].append(payload)
                                self.VendorDeviceDict[srcVendor][srcMac]['TCP Payload Length'].append(payloadLen)
                            except:
                                continue
                                                
                if transportLayer == 'UDP':
                    self.__udpCheck(srcVendor, packet, srcMac)  

            self.pCount = self.pCount + 1        
        cap.close()       
        self.finish = time.perf_counter()

    def extract(self):
        self.__getContent()

    def packetCount(self):
        print(self.pCount)

    def result(self):
        totalDevices = 0
        for vendor in self.VendorDeviceDict.keys():
            totalDevices += len(self.VendorDeviceDict[vendor].keys())
        print(self.VendorDeviceDict)
        print('Device Count: ' + str(totalDevices))
        print('Packet Count: ' + str(self.pCount))        
        print(f'Finished in {round(self.finish,2)} seconds(s)')

if __name__ == '__main__':
    cap = extract()
    cap.extract()
    cap.result()
    quit()


# Dictionary Layout for Data
# {
#    'Vendor': {
#       'Device': {
#           'Payload': []
#           'Payload Length': []
#           'Window Size': []
#       }
#    }
# }
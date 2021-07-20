#include<bits/stdc++.h>
#include <sys/socket.h> // for socket, PF_PACKET, SOCK_RAW
#include <netinet/in.h> // for IPPROTO_TCP
#include <arpa/inet.h> // for htons, IPPROTO_TCP
#include <netinet/if_ether.h> // ETH_P_ALL decided not to use only tcp packet will suffice
#include <unistd.h> // close()
#include <linux/ip.h> // for iphdr
#include <linux/tcp.h> // for tcphdr
#include <linux/if_packet.h> // for sockaddr_ll
#include <sys/ioctl.h> // for ioctl
#include <net/if.h> // for freq
#include <netinet/ether.h> // ether_aton
using namespace std;
unsigned char victim1MAC[6];
unsigned char victim2MAC[6];
unsigned char attackerMAC[6];
unsigned char victim1IP[4];
unsigned char victim2IP[4];
unsigned char attackerIP[4];
int rawSendSocket;

string SRC_MAC; //"02:42:0a:09:00:05"
string DST_MAC; // "02:42:0a:09:00:06"
string ATT_MAC; // "02:42:0a:09:00:69"
string SRC_IP; // "10.9.0.5"
string DST_IP; // "10.9.0.6"
string ATT_IP; // "10.9.0.105"

typedef struct EthernetHeader
{
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short protocol;

}EthernetHeader;

typedef struct ArpHeader
{
    unsigned short hardwareType;
    unsigned short protocolType;
    unsigned char hardwareAdressLength;
    unsigned char protocolAdressLength;
    unsigned short opcode;
    unsigned char souceHardware[6];
    unsigned char sourceProtocol[4];
    unsigned char destHardware[6];
    unsigned char destProtocol[4];

}ArpHeader;


int bindRawSocketToInterface(char *device, int rawSocket)
{
    cout<<"inside bind socket"<<endl<<flush;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    bzero(&sll,sizeof(sll));
    bzero(&ifr,sizeof(ifr));

    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if((ioctl(rawSocket, SIOCGIFINDEX, &ifr)) == -1 )
    {
        cout<<"error getting interface index"<<endl<<flush;
        exit(-1);
    }

    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    cout<<"calling bind"<<endl;
    if((bind(rawSocket, (struct sockaddr *)&sll, sizeof(sll)))==-1)
    {
        cout<<"error binding raw socket to interface"<<endl<<flush;
        exit(-1);
    }
    cout<<"exiting bind"<<endl<<flush;
    return 1;

}

void printUnsignedCharArr(char *verbose, unsigned char* buf, int bufSize)
{
    cout<<verbose;
    for(int i=0;i<bufSize;i++)
    {
        short t = buf[i];
        printf("%.2x ",t);
    }
    cout<<endl;
}

void craftARPFrame(unsigned char* buf, unsigned char* victimMAC, unsigned char* victimIP, unsigned char* attackerMAC, unsigned char* spoofedIP)
{
    cout<<"inside craftARPFrame"<<endl<<flush;
    int arpLen = sizeof(EthernetHeader)+sizeof(ArpHeader);
    EthernetHeader *eth = (EthernetHeader *)buf;
    memcpy(eth->source, (void *)attackerMAC, 6);
    memcpy(eth->destination, (void *)victimMAC, 6);
    eth->protocol = htons(ETHERTYPE_ARP);

    // cout<<"hey"<<endl<<flush;

    ArpHeader *arp = (ArpHeader *) (buf + sizeof(EthernetHeader));
    arp->hardwareType = htons(ARPHRD_ETHER);
    arp->protocolType = htons(ETHERTYPE_IP);
    arp->hardwareAdressLength = 6;
    arp->protocolAdressLength = 4;
    arp->opcode = htons(ARPOP_REPLY);
    // cout<<"hey1"<<endl<<flush;
    memcpy(arp->souceHardware, (void *)attackerMAC,6);
    memcpy(arp->destHardware, (void *)victimMAC,6);
    // arp->sourceProtocol = spoofedIP;
    // arp->destProtocol = victimIP;
    memcpy(arp->sourceProtocol, (void *)spoofedIP,4);
    memcpy(arp->destProtocol, (void *)victimIP,4);

    printUnsignedCharArr("ARP frame: ",buf,arpLen);
    cout<<"exiting crafting"<<endl<<flush;

}

void craftARPRequestFrame(unsigned char* buf, unsigned char* victim1MAC, unsigned char* victim1IP, unsigned char* victim2MAC, unsigned char* victim2IP)
{
    cout<<"inside craftARPRequestFrame"<<endl<<flush;
    int arpLen = sizeof(EthernetHeader)+sizeof(ArpHeader);
    EthernetHeader *eth = (EthernetHeader *)buf;
    memcpy(eth->source, (void *)victim1MAC, 6);
    memcpy(eth->destination, (void *)victim2MAC, 6);
    eth->protocol = htons(ETHERTYPE_ARP);

    // cout<<"hey"<<endl<<flush;

    ArpHeader *arp = (ArpHeader *) (buf + sizeof(EthernetHeader));
    arp->hardwareType = htons(ARPHRD_ETHER);
    arp->protocolType = htons(ETHERTYPE_IP);
    arp->hardwareAdressLength = 6;
    arp->protocolAdressLength = 4;
    arp->opcode = htons(ARPOP_REQUEST);
    // cout<<"hey1"<<endl<<flush;
    memcpy(arp->souceHardware, (void *)victim1MAC,6);
    memcpy(arp->destHardware, (void *)victim2MAC,6);
    // arp->sourceProtocol = spoofedIP;
    // arp->destProtocol = victimIP;
    memcpy(arp->sourceProtocol, (void *)victim1IP,4);
    memcpy(arp->destProtocol, (void *)victim2IP,4);

    printUnsignedCharArr("ARP frame: ",buf,arpLen);
    cout<<"exiting crafting"<<endl<<flush;


}


int main(int argc, char* argv[])
{
    if(argc!=7)
    {
        cout<<"wrong input format!"<<endl;
        exit(-1);
    }
    SRC_MAC = string(argv[1]);
    DST_MAC = string(argv[2]);
    ATT_MAC = string(argv[3]);
    SRC_IP = string(argv[4]);
    DST_IP = string(argv[5]);
    ATT_IP = string(argv[6]);

    memcpy(victim1MAC,ether_aton(SRC_MAC.c_str()),6);
    memcpy(victim2MAC,ether_aton(DST_MAC.c_str()),6);
    memcpy(attackerMAC,ether_aton(ATT_MAC.c_str()),6);
    in_addr_t t1=(inet_addr(SRC_IP.c_str())); // 10.9.0.5
    in_addr_t t2=(inet_addr(DST_IP.c_str())); // 10.9.0.6
    in_addr_t t3=(inet_addr(ATT_IP.c_str())); // 10.9.0.105
    memcpy(victim1IP,&t1 , 4);
    memcpy(victim2IP,&t2 , 4);
    memcpy(attackerIP,&t3 , 4);
    


    size_t pktBufSize = 10*1024;
    unsigned char pktBuf[pktBufSize];// 10kb space // has to be unsigned otherwise prints bad hex dump
    rawSendSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(rawSendSocket<0)
    {
        cout<<"kill meh"<<endl;
        return -5;
    }
    if(bindRawSocketToInterface("eth0", rawSendSocket)!=1)
    {
        cout<<"kill meh again"<<endl;
        return -5;
    }
    cout<<"Socket opened successfully"<<endl;
    int arpLen = sizeof(EthernetHeader)+sizeof(ArpHeader);
    unsigned char *rawARP = new unsigned char[arpLen];
    // bool sendVictim1 = true;
    // int count = 0;
    // while(true)
    // {
    //     // cout<<"hello"<<endl<<flush;
    //     if(sendVictim1)
    //     {
    //         craftARPFrame(rawARP,victim1MAC,victim1IP,attackerMAC,victim2IP);
    //     }
    //     else
    //     {
    //         craftARPFrame(rawARP,victim2MAC,victim2IP,attackerMAC,victim1IP);
    //     }
    //     // cout<<"hey"<<endl<<flush;
    //     cout<<"ARP NO. "<<count<<endl<<flush;
    //     cout<<"total sent: "<<write(rawSendSocket, rawARP, arpLen)<<endl;
        
    //     sendVictim1 = sendVictim1? false: true; 
    //     cout<<"sendVictim1: "<<sendVictim1<<endl<<flush;
    //     count++;
    //     sleep(2);
        
    // }
    // craftARPRequestFrame(rawARP, victim1MAC, victim1IP, victim2MAC, victim2IP);
    // cout<<"total sent: "<<write(rawSendSocket, rawARP, arpLen)<<endl;
    
   
    int receiveLength = 0;
    while(true)
    {
        // cout<<"hi"<<endl<<flush;
        receiveLength = recv(rawSendSocket, rawARP, arpLen, 0);
        if(receiveLength == 42)
        {
            EthernetHeader * etherhdr = (EthernetHeader *)rawARP;
            if(ntohs(etherhdr->protocol) == 0x0806)
            {
                ArpHeader * arphdr = (ArpHeader *) (rawARP+sizeof(EthernetHeader));
                if(arphdr->opcode == ntohs(ARPOP_REPLY))
                {
                    bool t1 = memcmp(arphdr->sourceProtocol,victim2IP,4) == 0;
                    bool t2 = memcmp(arphdr->souceHardware,victim2MAC,6) == 0;

                    if(t1 == true && t2 == false)
                    {
                        cout<<"there is someone between machine 1 and machine 2"<<endl<<flush;
                    }
                }
            }
            
        }
        else if(receiveLength > 0)
        {
            cout<<"wrong packet received"<<endl<<flush;
        }

    }

    delete[] rawARP;

}
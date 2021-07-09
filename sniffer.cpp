#include<bits/stdc++.h>
#include <sys/socket.h> // for socket, PF_PACKET, SOCK_RAW
#include <netinet/in.h> // for IPPROTO_TCP
#include <arpa/inet.h> // for htons, IPPROTO_TCP
#include <netinet/if_ether.h> // ETH_P_ALL decided not to use only tcp packet will suffice
#include <unistd.h> // close()
#include <linux/ip.h> // for iphdr
#include <linux/tcp.h> // for tcphdr
using namespace std;
unsigned char vicitim1MAC[6];
unsigned char vicitim2MAC[6];
uint32_t victim1IP;
uint32_t victim2IP;

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
        // cout<<"from victim2 to victim1 packet"<<endl;
    }
    else if(t22 && t33)
    {
        // cout<<"from victim1 to victim2 packet"<<endl;
    }
    else
    {
        // cout<<"not a packet from victim1 to victim2 so won't be injecting packet"<<endl;
        return -5;
    }
    

    




    return 0;
    
}

int parsePacket(unsigned char* buf, int bufSize)
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

    bool t11 = victim1IP == ntohl(ipHeader->daddr);
    bool t22 = victim1IP == ntohl(ipHeader->saddr);
    bool t33 = victim2IP == ntohl(ipHeader->daddr);
    bool t44 = victim2IP == ntohl(ipHeader->saddr);
    // cout<<t11<<" "<<t22<<" "<<t33<<" "<<t44<<endl;
    if(t11 && t44)
    {
        cout<<"from victim2 to victim1 packet"<<endl;
        // forwardPacket(buf,bufSize);
    }
    else if(t22 && t33)
    {
        cout<<"from victim1 to victim2 packet"<<endl;
        // forwardPacket(buf,bufSize);
        // changePacket(buf,bufSize);
    }
    else
    {
        cout<<"not a packet from victim1 to victim2 so won't be injecting packet"<<endl;
        return -5;
    }
    

    




    return 0;
    
}

int main()
{
    unsigned char temp1[] =  {0x02, 0x42, 0x0a, 0x09, 0x00, 0x05};
    memcpy(vicitim1MAC, temp1 , 6);
    unsigned char temp2[] =  {0x02, 0x42, 0x0a, 0x09, 0x00, 0x06};
    memcpy(vicitim2MAC, temp2 , 6);
    victim1IP=0xa090005;
    victim2IP=0xa090006;
    // Destination MAC: 02 42 0a 09 00 06 
    // Source MAC: 02 42 0a 09 00 69 
    // Protocol Type: 08 00 
    // Destination IP: a090006
    // Source IP: a090005
    // Destination Port: 9090
    // Source Port: 55000
    // Payload size: 3
    // Application Layer Data: 68 69 0a 


    size_t pktBufSize = 10*1024;
    unsigned char pktBuf[pktBufSize];// 10kb space // has to be unsigned otherwise prints bad hex dump
    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(rawSocket<0)
    {
        cout<<"kill meh"<<endl;
        return -5;
    }
    cout<<"Socket opened successfully"<<endl;
    int totalCaptured = 0;
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
        if(filterPacket(pktBuf,sizeOfPkt)==0)
        {
            parsePacket(pktBuf,sizeOfPkt);
        }
    }
    close(rawSocket);
    cout<<"Socket closed"<<endl;
    return 0;
}
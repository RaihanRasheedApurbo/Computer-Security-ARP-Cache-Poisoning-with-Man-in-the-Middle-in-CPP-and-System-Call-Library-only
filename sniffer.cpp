#include<bits/stdc++.h>
#include <sys/socket.h> // for socket, PF_PACKET, SOCK_RAW
#include <netinet/in.h> // for IPPROTO_TCP
#include <arpa/inet.h> // for htons, IPPROTO_TCP
#include <netinet/if_ether.h> // ETH_P_ALL decided not to use only tcp packet will suffice
#include <unistd.h> // close()
#include <linux/ip.h> // for iphdr
#include <linux/tcp.h> // for tcphdr
using namespace std;
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
    if(bufSize >= sizeof(struct ethhdr))
    {
        ethHeader = (struct ethhdr*) buf;
        printUnsignedCharArr("Destination MAC: ",ethHeader->h_dest,6);
        printUnsignedCharArr("Source MAC: ",ethHeader->h_source,6);
        printUnsignedCharArr("Protocol Type: ",(unsigned char*)&ethHeader->h_proto,2);
    }
    else
    {
        printf("Ethernet header parsing failed\n");
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
        if(bufSize >= (sizeof(struct ethhdr) + ipHeader->ihl * 4))
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




    return 0;
    
}
int main()
{
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
        parsePacket(pktBuf,sizeOfPkt);
    }
    close(rawSocket);
    cout<<"Socket closed"<<endl;
    return 0;
}
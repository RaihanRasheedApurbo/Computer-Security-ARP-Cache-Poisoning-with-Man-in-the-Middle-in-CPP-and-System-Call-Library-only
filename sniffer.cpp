#include<bits/stdc++.h>
#include <sys/socket.h> // for socket, PF_PACKET, SOCK_RAW
#include <netinet/in.h> // for IPPROTO_TCP
#include <arpa/inet.h> // for htons, IPPROTO_TCP
#include <netinet/if_ether.h> // ETH_P_ALL decided not to use only tcp packet will suffice
#include <unistd.h> // close()
using namespace std;
void printPacket(unsigned char* buf, int bufSize)
{
    for(int i=0;i<bufSize;i++)
    {
        short t = buf[i];
        printf("%x ",t);
    }
    cout<<endl;
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
        printPacket(pktBuf,sizeOfPkt);
    }
    close(rawSocket);
    cout<<"Socket closed"<<endl;
    return 0;
}
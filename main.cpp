#include<bits/stdc++.h>
#include <sys/socket.h> // for socket, PF_PACKET, SOCK_RAW
#include <arpa/inet.h> // for htons
#include <netinet/if_ether.h> // ETH_P_ALL
#include <unistd.h> // close()
using namespace std;
int main()
{
    char *pktBuf = new char[10*1024]; // 10kb space
    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    close(rawSocket);
    return 0;
}
Here I was asked to demonstrate ARP Cache Poisoning with Man in the Middle Attack.
There wasn't any other specification given. So I could choose my own platform. Only two constrain was given to me and that were I have to use c/c++ to do everything and I can't use any third party library. So I had to do everything in linux system calls libraries.

Theoretical discussion can be found in project reports/project proposal.pdf and complete attack demonstration walkthrough can be found in project reports/final network security report.pdf

This is one of my level 4 term 1 computer security projects. 

In order to demonstrate this attack successfully we need 3 machines. Two host and one attacker. I used seed labs project demonstration infrastructure. I also used their ARP Attack project as my own project specification. But in that project specification (ARP_Attack.pdf) they instructed to do everything in python scapy. So I implemented everything in c++ and I also implemented one component of the project in scapy as well to find out the difference in implementation. 

Docker-compose.yml can be used to spin all the necessary containers. volumes folder has all the necessary files needed for attack demonstration which is mounted by specific containers described in the docker-compose.yml. Basic docker understanding is a must after reading the ARP_Attack.pdf. 


In order to poison ARP cache of victim I wrote spoofer (volumes/spoofer.cpp). This sends both the victims wrong ARP reply.

I have also implemented sniffer in python (volumes/pySniffer.py) as it helped me to debug my c++ implmentation of sniffer (volumes/sniffer.cpp).


I also implemented a trivial spoofDefender (volumes/defendSpoofing). This program sniffs only arp packets and check whether Host 2's MAC address matches with the known MAC address by Host1 of Host2.

bash scripts were used for my convenience when I was coding. Feel free to use those. I have written difference shell script for compiling and running because I had to compile in host of the docker and run in a docker container as docker containers do not have gcc installed in them. I also took help from wireshark to understand frame that I should send and that I was sending.



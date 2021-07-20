# sudo ./sniffer
#without sudo it doesn't work in ubuntu 20.0.lts
#but in container we might need to remove sudo
#define SRC_MAC "02:42:0a:09:00:05"
#define DST_MAC "02:42:0a:09:00:06"
#define ATT_MAC "02:42:0a:09:00:69"
#define SRC_IP "10.9.0.5"
#define DST_IP "10.9.0.6"
#define ATT_IP "10.9.0.105"

./sniffer 02:42:0a:09:00:05 02:42:0a:09:00:06 02:42:0a:09:00:69 10.9.0.5 10.9.0.6 10.9.0.105 



# network 

빌드 및 실행 방법
sudo apt update
sudo apt install libpcap-dev

gcc -o tcp_only_sniffer tcp_only_sniffer.c -lpcap

sudo ./tcp_only_sniffer

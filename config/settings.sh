sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_max=33554432
mkdir ~/tmp_pcap_old
mkdir ~/wpcap
mkdir ~/wpcap_temp
mkdir /var/log/vehere
mkdir /var/log/vehere/json
#mkdir /var/lib/wifi_handshake
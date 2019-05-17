sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_max=33554432
mkdir ~/wpcap
mkdir ~/wpcap_temp
mkdir ~/json
sudo mkdir /var/lib/wifi_handshake
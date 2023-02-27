#!/bin/bash
#Script auto create trial user SSH
#will expired after 1 day

IP=`dig +short myip.opendns.com @resolver1.opendns.com`

Login=trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari="1"
Pass=`</dev/urandom tr -dc a-f0-9 | head -c9`

useradd -e `date -d "$hari days" +"%Y-%m-%d"` -s /bin/false -M $Login
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e ""
echo -e "====Trial SSH Account====" | lolcat
echo -e "Host: $IP" 
echo -e "OPENVPN TCP port : 1194"
echo -e "OPENVPN UDP port : 53"
echo -e "WS port : 80"
echo -e "PROXY port : 3128"
echo -e "PROXY port : 8080"
echo -e "PROXY port : 8000"
echo -e "Username: $Login"
echo -e "Password: $Pass\n"
echo -e "=========================" | lolcat
echo -e "Powered By: -xD'cRiz-" | lolcat
echo -e ""
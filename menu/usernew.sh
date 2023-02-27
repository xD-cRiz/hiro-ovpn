#!/bin/bash
#Script auto create user SSH

read -p "Username : " Login
read -p "Password : " Pass
read -p "Expired (day): " Activetime

IP=`dig +short myip.opendns.com @resolver1.opendns.com`
useradd -e `date -d "$Activetime days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e ""
echo -e "====SSH Account Information====" | lolcat
echo -e "Host: $IP"
echo -e "OPENVPN TCP port : 1194"
echo -e "OPENVPN UDP port : 53"
echo -e "WS port : 80"
echo -e "PROXY port : 3128"
echo -e "PROXY port : 8080"
echo -e "PROXY port : 8000"
echo -e "Username: $Login "
echo -e "Password: $Pass"
echo -e "-----------------------------" | lolcat
echo -e "Expiration: $exp"
echo -e "=============================" | lolcat
echo -e "Mod by xD'Criz"
echo -e ""

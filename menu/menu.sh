#!/bin/bash
#Menu
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CORTITLE='\033[1;41m'
SCOLOR='\033[0m'
banner='

██╗░░██╗██████╗░██╗░█████╗░██████╗░██╗███████╗
╚██╗██╔╝██╔══██╗╚█║██╔══██╗██╔══██╗██║╚════██║
░╚███╔╝░██║░░██║░╚╝██║░░╚═╝██████╔╝██║░░███╔═╝
░██╔██╗░██║░░██║░░░██║░░██╗██╔══██╗██║██╔══╝░░
██╔╝╚██╗██████╔╝░░░╚█████╔╝██║░░██║██║███████╗
╚═╝░░╚═╝╚═════╝░░░░░╚════╝░╚═╝░░╚═╝╚═╝╚══════╝'
echo -e "${CORTITLE}=================================================${SCOLOR}" 
echo -e "${CORTITLE}                SSHPLUS Ovpn/CLIENT              ${SCOLOR}"
echo -e "${CORTITLE}=================================================${SCOLOR}" 
echo -e "${RED}$banner${SCOLOR}"
echo -e ""
echo -e "======================================================" | lolcat
echo -e "\e[1;31m * menu\e[0m       ${GREEN}: Displays a list of available commands      	${SCOLOR}"
echo -e "\e[1;31m * usernew\e[0m    ${GREEN}: Creating an SSH Account       				${SCOLOR}"
echo -e "\e[1;31m * trial\e[0m      ${GREEN}: Create a Trial Account       					${SCOLOR}"
echo -e "\e[1;31m * delete\e[0m     ${GREEN}: Clearing SSH and OpenVPN Account       		${SCOLOR}"
echo -e "\e[1;31m * check\e[0m      ${GREEN}: Check User Login       						${SCOLOR}"
echo -e "\e[1;31m * member\e[0m     ${GREEN}: Check Member SSH and OpenVPN       			${SCOLOR}"
echo -e "\e[1;31m * restart\e[0m    ${GREEN}: Restart Service ssh, udp/openvpn/squid/ws     ${SCOLOR}"
echo -e "\e[1;31m * reboot\e[0m     ${GREEN}: reboot VPS       								${SCOLOR}"
echo -e "\e[1;31m * info\e[0m       ${GREEN}: System Information       						${SCOLOR}"
echo -e "\e[1;31m * about\e[0m      ${GREEN}: Information about auto install script       	${SCOLOR}"
echo -e "\e[1;31m * exit\e[0m       ${GREEN}: exit Putty/Connecbot/       					${SCOLOR}"
echo -e "=======================================================" | lolcat
echo -e ""
echo -e ""


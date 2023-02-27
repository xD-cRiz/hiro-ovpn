#!/bin/bash
# Script restart service dropbear,  squid3, openvpn, openssh
# Created by xD'Criz
systemctl restart openvpn@server
systemctl restart openvpn@server2
service squid3 restart
service openvpn restart
service ssh restart

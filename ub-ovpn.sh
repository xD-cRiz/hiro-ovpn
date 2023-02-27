#!/bin/bash
# UNBUNTU/DEBIAN
# Version: 2023

cp /usr/share/zoneinfo/Asia/Manila /etc/localtime

install_require()
{
  clear
  echo "Updating your system."
  {
    apt-get -o Acquire::ForceIPv4=true update
  } &>/dev/null
  clear
  echo "Installing dependencies."
  {
    apt-get -o Acquire::ForceIPv4=true install mysql-client -y
    apt-get -o Acquire::ForceIPv4=true install mariadb-server stunnel4 openvpn -y
    apt-get -o Acquire::ForceIPv4=true install dos2unix easy-rsa nano curl wget unzip jq virt-what net-tools -y
    apt-get -o Acquire::ForceIPv4=true install php-cli net-tools cron php-fpm php-json php-pdo php-zip php-gd  php-mbstring php-curl php-xml php-bcmath php-json -y
    apt-get -o Acquire::ForceIPv4=true install gnutls-bin pwgen python -y
  } &>/dev/null
}

install_squid()
{
clear
echo "Installing proxy."
{
#[[ ! -e /etc/apt/sources.list.d/trusty_sources.list ]] && {
#touch /etc/apt/sources.list.d/trusty_sources.list >/dev/null 2>&1
#echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | tee --append /etc/apt/sources.list.d/trusty_sources.list >/dev/null 2>&1
#}
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | tee --append /etc/apt/sources.list >/dev/null 2>&1
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | tee --append /etc/apt/sources.list.d/trusty_sources.list >/dev/null 2>&1
[[ $(grep -wc 'Debian' /etc/issue.net) != '0' ]] && {
apt install dirmngr -y >/dev/null 2>&1
[[ $(apt-key list 2>/dev/null | grep -c 'Ubuntu') == '0' ]] && {
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 >/dev/null 2>&1
}
}
apt update -y

apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
/bin/cat <<"EOM" >/etc/init.d/squid3
#! /bin/sh
#
# squid		Startup script for the SQUID HTTP proxy-cache.
#
# Version:	@(#)squid.rc  1.0  07-Jul-2006  luigi@debian.org
#
### BEGIN INIT INFO
# Provides:          squid
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Squid HTTP Proxy version 3.x
### END INIT INFO

NAME=squid3
DESC="Squid HTTP Proxy"
DAEMON=/usr/sbin/squid3
PIDFILE=/var/run/$NAME.pid
CONFIG=/etc/squid3/squid.conf
SQUID_ARGS="-YC -f $CONFIG"

[ ! -f /etc/default/squid ] || . /etc/default/squid

. /lib/lsb/init-functions

PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -x $DAEMON ] || exit 0

ulimit -n 65535

find_cache_dir () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+[^'"$w"']\+['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
        [ -n "$res" ] || res=$2
        echo "$res"
}

grepconf () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
	[ -n "$res" ] || res=$2
	echo "$res"
}

create_run_dir () {
	run_dir=/var/run/squid3
	usr=`grepconf cache_effective_user proxy`
	grp=`grepconf cache_effective_group proxy`

	if [ "$(dpkg-statoverride --list $run_dir)" = "" ] &&
	   [ ! -e $run_dir ] ; then
		mkdir -p $run_dir
	  	chown $usr:$grp $run_dir
		[ -x /sbin/restorecon ] && restorecon $run_dir
	fi
}

start () {
	cache_dir=`find_cache_dir cache_dir`
	cache_type=`grepconf cache_dir`
	run_dir=/var/run/squid3

	#
	# Create run dir (needed for several workers on SMP)
	#
	create_run_dir

	#
	# Create spool dirs if they don't exist.
	#
	if test -d "$cache_dir" -a ! -d "$cache_dir/00"
	then
		log_warning_msg "Creating $DESC cache structure"
		$DAEMON -z -f $CONFIG
		[ -x /sbin/restorecon ] && restorecon -R $cache_dir
	fi

	umask 027
	ulimit -n 65535
	cd $run_dir
	start-stop-daemon --quiet --start \
		--pidfile $PIDFILE \
		--exec $DAEMON -- $SQUID_ARGS < /dev/null
	return $?
}

stop () {
	PID=`cat $PIDFILE 2>/dev/null`
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	#
	#	Now we have to wait until squid has _really_ stopped.
	#
	sleep 2
	if test -n "$PID" && kill -0 $PID 2>/dev/null
	then
		log_action_begin_msg " Waiting"
		cnt=0
		while kill -0 $PID 2>/dev/null
		do
			cnt=`expr $cnt + 1`
			if [ $cnt -gt 24 ]
			then
				log_action_end_msg 1
				return 1
			fi
			sleep 5
			log_action_cont_msg ""
		done
		log_action_end_msg 0
		return 0
	else
		return 0
	fi
}

cfg_pidfile=`grepconf pid_filename`
if test "${cfg_pidfile:-none}" != "none" -a "$cfg_pidfile" != "$PIDFILE"
then
	log_warning_msg "squid.conf pid_filename overrides init script"
	PIDFILE="$cfg_pidfile"
fi

case "$1" in
    start)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Starting $DESC" "$NAME"
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	if stop ; then
		log_end_msg $?
	else
		log_end_msg $?
	fi
	;;
    reload|force-reload)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_action_msg "Reloading $DESC configuration files"
	  	start-stop-daemon --stop --signal 1 \
			--pidfile $PIDFILE --quiet --exec $DAEMON
		log_action_end_msg 0
	fi
	;;
    restart)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Restarting $DESC" "$NAME"
		stop
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    status)
	status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit 3
	;;
    *)
	echo "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|status}"
	exit 3
	;;
esac

exit 0
EOM

chmod +x /etc/init.d/squid3
/sbin/update-rc.d squid3 defaults

cd /usr/share/squid3/errors/English/
echo "acl IP dst $(curl -s https://api.ipify.org)
http_access allow IP
http_access deny all
http_port 8080
http_port 3128
http_port 8000
error_directory /usr/share/squid3/errors/English"| tee /etc/squid3/squid.conf

echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Criz Romero</title>
</head>

<body bgcolor="#ffffff">
<center>
  <font color="#FF0000"><h1><strong>Criz Romero</strong></h1></font></center>
</body>
</html>' | tee ERR_ACCESS_DENIED ERR_FTP_FORBIDDEN ERR_PRECONDITION_FAILED ERR_ACL_TIME_QUOTA_EXCEEDED ERR_FTP_NOT_FOUND ERR_PROTOCOL_UNKNOWN ERR_AGENT_CONFIGURE ERR_FTP_PUT_CREATED ERR_READ_ERROR ERR_AGENT_WPAD ERR_FTP_PUT_ERROR ERR_READ_TIMEOUT ERR_CACHE_ACCESS_DENIED ERR_FTP_PUT_MODIFIED ERR_SECURE_CONNECT_FAIL ERR_CACHE_MGR_ACCESS_DENIED  ERR_FTP_UNAVAILABLE ERR_SHUTTING_DOWN ERR_CANNOT_FORWARD ERR_GATEWAY_FAILURE ERR_SOCKET_FAILURE ERR_CONFLICT_HOST ERR_ICAP_FAILURE ERR_TOO_BIG ERR_CONNECT_FAIL ERR_INVALID_REQ ERR_UNSUP_HTTPVERSION ERR_DIR_LISTING ERR_INVALID_RESP ERR_UNSUP_REQ ERR_DNS_FAIL ERR_INVALID_URL ERR_URN_RESOLVE ERR_ESI ERR_LIFETIME_EXP ERR_WRITE_ERROR ERR_FORWARDING_DENIED ERR_NO_RELAY ERR_ZERO_SIZE_OBJECT ERR_FTP_DISABLED ERR_ONLY_IF_CACHED_MISS ERR_FTP_FAILURE > /dev/null
update-rc.d squid3 defaults
systemctl enable squid3
systemctl restart squid3
} &>/dev/null
}

install_openvpn()
{
clear
echo "Installing openvpn."
{
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /etc/openvpn/server
mkdir -p /var/www/html/stat
touch /etc/openvpn/server.conf
touch /etc/openvpn/server2.conf

echo '# Openvpn Configuration
dev tun
port 53
proto udp
topology subnet
server 10.30.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
script-security 3
/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
#log /etc/openvpn/server/udpserver.log
status /etc/openvpn/server/udpclient.log
status-version 2
verb 3' > /etc/openvpn/server.conf

echo '# Openvpn Configuration
dev tun
port 1194
proto tcp
topology subnet
server 10.20.0.0 255.255.252.0
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh none
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
cipher none
ncp-disable
auth none
sndbuf 0
rcvbuf 0
keepalive 10 120
persist-key
persist-tun
ping-timer-rem
reneg-sec 0
user nobody
group nogroup
client-to-client
username-as-common-name
verify-client-cert none
script-security 3
/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
push "persist-key"
push "persist-tun"
push "dhcp-option DNS 8.8.8.8"
push "redirect-gateway def1 bypass-dhcp"
push "sndbuf 0"
push "rcvbuf 0"
#log /etc/openvpn/server/tcpserver.log
status /etc/openvpn/server/tcpclient.log
status-version 2
verb 3' > /etc/openvpn/server2.conf

cat << EOF > /etc/openvpn/easy-rsa/keys/ca.crt
-----BEGIN CERTIFICATE-----
MIIDljCCAv+gAwIBAgIJANCSvxmI6CTbMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYD
VQQGEwJQSDEUMBIGA1UECBMLUXVlem9uIENpdHkxEzARBgNVBAcTCk5vdmFsaWNo
ZXMxFDASBgNVBAoTC0NyaXogUm9tZXJvMRcwFQYDVQQDEw5Dcml6IFJvbWVybyBD
QTEmMCQGCSqGSIb36imxTKN5PetbWHULZ8JiRrxjMevYrgmHh0BnbWFpbC5jb20wHhcNMTgw
MTE2MDkzMzAwWhcNMjgwMTE0MDkzMzAwWjCBjzELMAkGA1UEBhMCUEgxFDASBgNV
BAgTC14HXBNXSgqRqi1QYk5WALJJg1zQQXuctjkOb3ZhbGljaGVzMRQwEgYDVQQKEwtD
cml6IFJvbWVybzEXMBUGA1UEAxMOQ3JpeiBSb21lcm8gQ0ExJjAkBgkqhkiG9w0B
CQEWF2NyaXp0YW5yb21lcm9AZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQCfJ3HQjwhA++d3d99zaev2Ta0yZHWSQDzslJdFFVE2oe5SN1F9vWvY
qkaEW7RbTspvL4xEdK3VjvykrfD90HJxykGmbVl/Uy5Exxu59f8g+UWJ4vcoSwGa
JqWNQpNfLf7KRUdLcDjlbNmAkQCDVjSV/Qecjk8hozWcA5Hsq79jpwIDAQABo4H3
MIH0MB0GA1UdDgQWBBROijK153u1pIMYAYDeQYDlCMc+WjCBxAYDVR0jBIG8MIG5
gBROijK153u1pIMYAYDeQYDlCMc+WqGBlaSBkjCBjzELMAkGA1UEBhMCUEgxFDAS
BgNVBAgTC189VmrDcs3Y261RvbE2DMvZqvb95JrjrisOb3ZhbGljaGVzMRQwEgYDVQQK
EwtDcml6IFJvbWVybzEXMBUGA1UEAxMOQ3JpeiBSb21lcm8gQ0ExJjAkBgkqhkiG
9w0BCQEWF2NyaXp0YW5yb21lcm9AZ21haWwuY29tggkA0JK/GYjoJNswDAYDVR0T
BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQATuwx5OO3EiSaswG06GZu+Hcxj2pNt
sCenDElWHH+XO/mEG5mSWsEgcYADfLCy7asle66oziZd1Silf2pc/tZ+oymcRa7p
cGlR4YVIkEADk6MhbIgHUIKeaFtE34+dwss/o4peVdFPghXpsrcdDn0hd7vr1Ux7
uuRjFK0H+G6kmg==
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=PH, ST=Quezon City, L=Novaliches, O=Criz Romero, CN=Criz Romero CA/emailAddress=criztanromero@gmail.com
        Validity
            Not Before: Jan 16 09:33:43 2018 GMT
            Not After : Jan 14 09:33:43 2028 GMT
        Subject: C=PH, ST=Quezon City, L=Novaliches, O=Criz Romero, CN=server/emailAddress=criztanromero@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:c7:0f:e9:90:17:ab:99:11:e7:2f:83:b0:d5:15:
                    da:7c:de:61:63:75:59:34:02:ec:fa:6d:d3:a4:51:
                    ce:b9:21:0a:41:65:68:45:c1:b2:46:c5:f0:f2:db:
                    83:78:93:f5:94:14:01:f4:57:0b:c7:6d:d5:21:36:
                    20:7a:fe:df:2d:78:fa:8f:2e:59:2c:26:4a:e2:5e:
                    b5:c8:ec:e1:e2:0d:3c:3b:0d:d5:b6:c6:0a:c6:69:
                    76:fe:01:bf:f3:26:7e:a6:82:49:ba:6c:8f:4b:88:
                    83:ac:07:5d:dc:f7:db:8e:67:46:c4:b9:67:dc:60:
                    40:5f:07:dd:1b:73:6f:62:53
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                57:6A:F0:53:64:4D:7C:32:76:50:15:D4:4A:F1:F2:EA:19:90:46:6D
            X509v3 Authority Key Identifier: 
                keyid:4E:8A:32:B5:E7:7B:B5:A4:83:18:01:80:DE:41:80:E5:08:C7:3E:5A
                DirName:/C=PH/ST=Quezon City/L=Novaliches/O=Criz Romero/CN=Criz Romero CA/emailAddress=criztanromero@gmail.com
                serial:D0:92:BF:19:88:E8:24:DB

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha1WithRSAEncryption
         11:98:6b:ef:5f:8c:06:b8:9f:07:a4:c5:32:d8:12:a8:67:96:
         b4:72:a1:65:b5:6d:e8:c8:3b:7e:a3:3b:3c:41:f2:48:92:24:
         fe:d2:21:c8:11:99:d5:65:a1:cd:3e:b3:3a:f6:fd:c1:b8:71:
         d0:64:9f:93:3d:b8:0b:af:0f:92:2b:07:40:32:b6:32:4b:8f:
         9a:49:bb:79:e5:49:2b:5f:3d:f2:ca:a4:39:90:71:19:c3:30:
         1c:ef:71:aa:72:a1:df:68:fa:25:cb:88:b0:c7:4c:91:ef:2b:
         2d:95:50:29:d4:cb:59:e9:9c:86:52:66:36:e7:02:73:67:07:
         9a:d3
-----BEGIN CERTIFICATE-----
MIID8DCCA1mgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBjzELMAkGA1UEBhMCUEgx
FDASBgNVBAgTC19FVasMhwTCYA8dzHomKqQfW5YNsfqW4u6Ob3ZhbGljaGVzMRQwEgYD
VQQKEwtDcml6IFJvbWVybzEXMBUGA1UEAxMOQ3JpeiBSb21lcm8gQ0ExJjAkBgkq
hkiG9w0BCQEWF2NyaXp0YW5yb21lcm9AZ213o892f2AznkmhLvJLA2JKyPMvx5Evi7g30
M1oXDTI4MDExNDA5MzM0M1owgYcxCzAJBgNVBAYTAlBIMRQwEgYDVQQIEwtRdWV6
b24gQ2l0eTETMBEGA1UEBxMKTm92YWxpY2hlczEUMBIGA1UEChMLQ3JpeiBSb21l
cm8xDzANBgNVBAMTBnNlcnZlcjEmMCQGCSqGSIb3Cm4HTdRoJrRt6G2cKCLEaobwUBcuzkYjU
b0BnbWFpbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMcP6ZAXq5kR
5y+DsNUV2nzeYWN1WTQC7Ppt06RRzrkhCkFlaEXBskbF8PLbg3iT9ZQUAfRXC8dt
1SE2IHr+3y14+o8uWSwmSuJetcjs4eINPDsN1bbGCsZpdv4Bv/MmfqaCSbpsj0uI
g6wHXdz36imxTKN5PetbWHULZ8JiRrxjMevYrgmHhIIBXDAJBgNVHRMEAjAA
MBEGCWCGSAGG+EIBAQQEAwIGQDA0BglghkgBhvhCAQ0EJxYlRWFzeS1SU0EgR2Vu
ZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUV2rwU2RNfDJ2UBXU
SvHy6hmQRm0wgcQGA1UdIwSBvDCBuYAUTooyted7taSDGAGA3kGA5QjHPlqhgZWk
gZIwgY8xCzAJBgNVBAYTAlBIMRQwEgYDVQQIEwtRdWV6b24gQ2l0eTETMBEGA1UE
BxMKTm92YWxpY2hlczEUMBIGA1UEChMLQ3JpeiBSb21lcm8xFzAVBgNVBAMTDkNy
aXogUm9tZXJvIENBMSYwJAYJKoZIhvcNAQkBFhdjcml6dGFucm9tZXJvQGdtYWls
LmNvbYIJANCSvxmI6CTbMBMGA1JZxxKaz1soSt1rmyksh1gZmPttBSwDVe6IF
oDANBgkqhkiG9w0BAQUFAAOBgQARmGvvX4wGuJ8HpMUy2BKoZ5a0cqFltW3oyDt+
ozs8QfJIkiT+0iHIEZnVZaHNPrM69v3BuHHQZJ+TPbgLrw+SKwdAMrYyS4+aSbt5
5UkrXz3Cm4HTdRoJrRt6G2cKCLEaobwUBcuzkYjUly4iwx0yR7ystlVAp1MtZ6ZyGUmY25wJz
Zwea0w==
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.key
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMcP6ZAXq5kR5y+D
sNUV2nzeYWN1WTQC7Ppt06RRzrkhCkFlaEXBskbF8PLbg3iT9ZQUAfRXC8dt1SE2
IHr+3y14+o8uWSwmSuJetcjs4eINPDsN1bbGCsZpdv4Bv/MmfqaCSbpsj0uIg6wH
Xdz3D8WcMtdfW8veJJGPe1xaRRsDfzxtXKKFilZnbTlNb9rAywWH5S1TvB
EnLwDGD9O/0GTUuNfcNG+W+2EsDjnYhl5RGjeKOlFJoYoZAf7swdZ+j96l/5dp0o
V+qEoXvzbdafC2arCrNMPRWEYkAe+kcyFON1//Ib6fXxFSCRgqmm0EiTaKcNo23E
/3LVvMZvcpDw7mR4WQJBAOT7Nbwalfm3bLRa0PhROgWfzQPb7TuZGTQyHwO8UCMw
zjl/3Xz0tL8LEKrDw29V3g5vEesMyqOcqttrFzyVLgcCQQDejPEFsgtnkuZ2IdbJ
wwEUQsQ8jpydZnlsqp/XQ9WvbI8iMvizfdxVCQg6pMHfR3yOMnjEhuettX9zIa2P
2ZZVAkAmrJs1yxO7mpRcnd4forB3FLduyG14HHKaU0DTw7GRUAP0yDjjiv0gK0FE
Zk4S9uDLdU0EcyOioKpm5t6E1/lvAkEAw9wMXnPUH6IkGwEq88Qf1gHwjE8CPHAs
GtuK8rtrewiya2mqgOUanOfnCx1m1icm0kpPCL6ldLZP5TZVdk0LRQJBAIqDC19X
0UbVlvXIq+gUgkumM/uG/Rkl1mudocUGWcOiC5bEq/d31fadU9ymFhVAcKsE7AHx
3sTf1uNv2z3sg/g=
-----END PRIVATE KEY-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIGHAoGBAP69YIQHcKykberMr8M2dBR4B9hFdVxlb3mjeyQEWJmkKITJtL05PzP0
P4bOlv3fJdOeWYDVFqBKQ8fHQKOc2Q4okuWxXO+9sWGDroBpeBKo/1AH/V8w6Y7A
JGbGJleAFk+g73zfMAuEeQ0xLm3tfvbN5tgS8G1wnO/OBYdKGVV7AgEC
-----END DH PARAMETERS-----
EOF

chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
systemctl restart openvpn@server
systemctl restart openvpn@server2
update-rc.d openvpn defaults
systemctl enable openvpn
}&>/dev/null
}

install_stunnel() {
  {
cd /etc/stunnel/

echo "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA+A7kkUwhEiVc3V2vQMCnkXxhU/U9eXVgcyMBLDjZ5tcYP41I
wfhrNH3kNIGLc/C1w9eM13hX7lxaZlInMb4ZWfDOy8/WLNC4XdT/74ucGqtlNDvu
bCL617hr0NyLkf9KRxQlaa/Mc7qu18sMyX+AUJsKLrigxXQC3XQ7S/i3YfGBU6x1
V9G+aXq2t3z/dAQK6mcUj/5YArEBc1YpdJpEkSXyMfWZByjE5QlBeHfe/eGnxOoV
3VLFObil/FdwsK/F4hAW4SWSLAf3KY8IjiicRgXk3Vcm5eQAftsluuNdMFNR+0wp
z1jHl7G6mTwTXyAuB1lvyRPO8iSyueAwRfAgTwIDAQABAoIBAQC14oWqHD4rhgXf
su/r9Ndpj9/1pd6bjntYMRSNDmqIHrOC9d+hirtg0+ZesZZFPvyoSwbUf0NKXaFT
YW2nxZHlJvMa8pxCZBCrjKDVTnL6Ay7D7CXYWJXBU1KK5QvZ02ztTVJZejPZr8rA
I/yOStUVRXlj5LDN13Fsuk5re9rrPowiNRvHp4xCXpjHXSWdC2OQEhukp2ycjwU3P
RHErEC7Gkhdo7netjwOmBvysikPmtheE8IZOpx/yok+pRB1zrzWExAM7nZHNQsR4
jF1xJiaQ4/9a7PGNvbHOj8YarbWxGPHzrWYvrzz4P8ZwgWnv5gdOWsBJTG+sUNJ2
n5dCXlIBAoGBAPzWxrs7ACW8ZUwqvKyhTjAAmpMz6I/VQNbtM/TEKCUpMaXXCSar
ItnmSXwt29c0LSoHifwlBenUx+QB/o5qr2idbbJRbU1Pz4PcIRCdKcu0t4PoeJJM
T6CzXNs46Sg98HZ46WW0HesI8UNbwa8vj8B92O9Z5CoFOStYb4cRxFbPAoGBAPso
0Lx+ZCqA3+++BFaqsFjdh8YL3UOjm1oSn/ip1Stgv0Jl862RQA3aB5nNMutuPBIc
gAlb14HXBNXSgqRqi1QYk5WALJJg1zQQXuctjklrjSkyNxmP2LkCJFpGBm1AOc5meL0avXH
yzmqEdOvXKC06D0eZlBtLnfITwRgcjMoiHxF8f6BAoGAeuA+ULvJxI0chbm3XAZA
o1+Hv8ZYXZ58FnfM6kVyZSzx7fDlh59gHpmmWO1Ii/vVfzmOu7WafBtm0c6OUdRT
TvpDV4fvIMWKykBu6U4YA+Hd1gNipWbkw+qnU/sChQYlGM6GT2ELsS/1YJD1PhhV
Om1uwlPjaPCE6iXefbwKuU0CgYEA4274ZlhFuD9viZeWMizq9+3TT0HbIa77tLr8
5Z5VDKzVRPkxilDnoiN3kozAuXTfLL9mKhNgR7tG0/EfQjjwXxpWSyZpvgcQArjT
4ZP+16Y3bAN2xsZWLqE7qib89QnD+cDshNE+x2QbCuQHEaF/oQDdfVaER0BW6YCg
53gnRQECgYEA0CbUEO4JPIN6djkwX8a19FVasMhwTCYA8dzHomKqQfW5YNsfqW4u6lULzZlS
ezC6w+/xCAP2jU6qOPR0aQV1NRaZfZpAQ2q6e2W4cM2xrHCebr2fr7PE2/A/XHU2dl
OpQXVN1JwM0kcBY8IaTS22CRm1NRaZfZpAQ2q6e2W4cM2xrHCebr2fr7PE2=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIID0TCCArmgAwIBAgIJALf1kKi2R1g3MA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV
BAYTAlBIMQswCQYDVQQIDAJRQzELMAkGA1AfqaR9bb1n6FjQ1YVA5x9Gi5w8a43thN1
TjEUMBIGA1UECwwLY3FrLXZwbi5jb20xEDAOBgNVBAMMB3hELWNSaXoxHTAbBgkq
hkiG9w0BCQEWDmNyaXpAZ21EuBkLSJ3bibV93Qd9gCHTPi8J4fFu5ehPOFoXDTIxMDcw
MTE3MDMxOFowfzELMAkGA1UEBhMCUEgxCzAJBgNVBAgMAlFDMQswCQYDVQQHDAJR
QzEPMA0GA1UECgwGQ1FLVlBOMRQwEgYDVQQLDAtjcWstdnBuLmNvbTEQMA4GA1UE
AwwHeEQtY1JpejEdMBsGCSqGSIb3DQEJARYOY3JpekBnbWFpbC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD4DuSRTCESJVzdXa9AwKeRfGFT9T15
dWBzIwEsONnm1xg/jUjB+Gs0feQ0gYtz8LXD14zXeFfuXFpmUicxvhlZ8M7Lz9Ys
0Lhd1P/vi5waq2U0O+5sIvrXuGvQ3IuR/0pHFCVpr8xzuq7XywzJf4BQmwouuKDF
dALddDtL+Ldh8YFTrHVX0b5pera3fP90BArqZxSP/lgCsQFzVil0mkSRJfIx9ZkH
KMTlCUF4d9794afE6hXdUsU5uKX8V3Cwr8XiEBbhJZIsB/cpjwiOKJxGBeTdVybl
5AB+2yW6410wU1H7TCnPWMeXsbqZPBNfIC4HWW/JE87yJLK54DBF8CBPAgMBAAGj
UDBOMB0GA1UdDgQWBBRuC0gqbi8q0u1gRWkD4M6JOXfDMDAfBgNVHSMEGDAWgBRu
C0gqbi8q0u1gRWkD4M6JOXfDMDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBJ5uuyTBaCmXu5BDwvHWfn/BoRMLghdaoT5OkWNHlQ6XXriKOLvMrK1bnT
qU5JEiCF1vtJMjlG9okzFkgHdVzk7BgmwvFZXjCI1l8GhJiOMvqPweAiFYaV4Ny1
kIEocMeLLeX6MYTclHRQSeHWktE5tt0wPb25+jdd5Cf5Ikmzh1JLE2zKnZ8aRi5+
2p6D24FM7cYLkJUi5GJfWbMKy2kb5hgj89f9TSLa/SUUwxrktnIsntg7Mpj65SBc
qNRdgDhp7yhds2mQrFP+5yFpnE1Crw3YTBOr/4Oora6jYAG3gFDn6pwHK6SM1Iy0
xdnSR8pYhuw1OjnZhg6QV2lk68dM
-----END CERTIFICATE-----" >> stunnel.pem

echo "cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = 127.0.0.1:1194
accept = 443" >> stunnel.conf

cd /etc/default && rm stunnel4

echo 'ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""' >> stunnel4 

chmod 755 stunnel4
update-rc.d stunnel4 defaults
systemctl enable stunnel4
systemctl restart stunnel4
  } &>/dev/null
}

install_iptables(){
  {
echo -e "\033[01;31m Configure Sysctl \033[0m"
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000

/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o eth0 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o eth0 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o eth0 -j SNAT --to-source "$vps_ip"
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o eth0 -j SNAT --to-source "$vps_ip"
/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o venet0 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o venet0 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o venet0 -j SNAT --to-source "$vps_ip"
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o venet0 -j SNAT --to-source "$vps_ip"
/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o ens3 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o ens3 -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o ens3 -j SNAT --to-source "$vps_ip"
/sbin/iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o ens3 -j SNAT --to-source "$vps_ip"
/sbin/iptables-save > /etc/iptables_rules.v4
/sbin/ip6tables-save > /etc/iptables_rules.v6
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o eth0 -j SNAT --to-source "$vps_ip"
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o eth0 -j SNAT --to-source "$vps_ip"
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o venet0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o venet0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o venet0 -j SNAT --to-source "$vps_ip"
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o venet0 -j SNAT --to-source "$vps_ip"
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o ens3 -j SNAT --to-source "$vps_ip"
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o ens3 -j SNAT --to-source "$vps_ip"
iptables-save > /etc/iptables_rules.v4
iptables-save > /etc/iptables_rules.v6
/sbin/sysctl -p
sysctl -p
  }&>/dev/null
}

install_rclocal(){
  {
    wget -O /etc/ubuntu https://raw.githubusercontent.com/AmiaClaire/wget/main/ws-criz &> /dev/null
	dos2unix /etc/ubuntu
    chmod +x /etc/ubuntu
	screen -dmS socks python /etc/ubuntu
	wget --no-check-certificate https://raw.githubusercontent.com/AmiaClaire/wget/main/criz-rc -O /etc/systemd/system/rc-local.service
	chmod +x /etc/systemd/system/rc-local.service
    echo "#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
/sbin/iptables-restore < /etc/iptables_rules.v4
/sbin/ip6tables-restore < /etc/iptables_rules.v6
/sbin/sysctl -p
sysctl -p
screen -dmS socks python /etc/ubuntu
exit 0" >> /etc/rc.local
    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service
  }&>/dev/null
}
install_acount()
{
#############################
USER="criz"
PASS="romero"
#############################
useradd $USER
echo "$USER:$PASS" | chpasswd
}
install_done()
{
  clear
  echo "OPENVPN SERVER"
  echo "IP : $(curl -s https://api.ipify.org)"
  echo "OPENVPN TCP port : 1194"
  echo "OPENVPN UDP port : 53"
  echo "OPENVPN SSL port : 443"
  echo "WS port : 80"
  echo "PROXY port : 3128"
  echo "PROXY port : 8080"
  echo "PROXY port : 8000"
  echo
  echo
  history -c
  rm /root/.installer
  echo "Server will secure this server and reboot after 20 seconds"
  sleep 20
  /sbin/reboot
}

vps_ip=$(curl -s https://api.ipify.org)


install_require
install_squid
install_openvpn
install_stunnel
install_rclocal
install_iptables
install_acount
install_done

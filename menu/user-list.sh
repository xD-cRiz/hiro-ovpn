#!/bin/bash
echo "-------------------------------" | lolcat
echo "USERNAME          EXP DATE     " | lolcat
echo "-------------------------------" | lolcat
while read expired
do
        ACCOUNT="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $ACCOUNT | grep "Account expires" | awk -F": " '{print $2}')"
        if [[ $ID -ge 1000 ]]; then
        printf "%-17s %2s\n" "$ACCOUNT" "$exp"
        fi
done < /etc/passwd
all="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo "-------------------------------" | lolcat
echo "Account number: $all user"
echo "-------------------------------" | lolcat
echo -e "Powered By: -xD'cRiz-" | lolcat
echo -e ""

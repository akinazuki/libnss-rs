#!/bin/bash
username=$1
pubkey=$2
keytype=$3
fingerprint=$4
home=$5
echo "$username\n$pubkey\n$keytype\n$fingerprint\n$home" >> /tmp/ssh_auth.log

cat /tmp/authorized_keys
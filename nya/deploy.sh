#!/bin/bash
# export NSS_HTTP_API_REQUEST_TIMEOUT=30
# export NSS_HTTP_API_DEBUG=false
cat /etc/environment | grep NSS_HTTP_API_ENDPOINT
if [[ $? -ne "0" ]]
then
  echo "NSS_HTTP_API_ENDPOINT=$NSS_HTTP_API_ENDPOINT" >> /etc/environment
fi
TEST_USERNAME="test"
GLIBC_VER=`ldd --version | grep ldd | awk '{print $NF}'`
OS_VER=`cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | sed 's/"//g'`

cd /release/${TARGET}/release
cp libnss_${SO_NAME}.so libnss_${SO_NAME}.so.2
install -m 0644 libnss_${SO_NAME}.so.2 /lib
install -m 0644 libnss_${SO_NAME}.so.2 /usr/lib64
/sbin/ldconfig -n /lib /usr/lib

sed -i "s/^passwd:.*$/passwd:        files ${SO_NAME}/" /etc/nsswitch.conf
sed -i "s/^group:.*$/group:          files ${SO_NAME}/" /etc/nsswitch.conf
sed -i "s/^shadow:.*$/shadow:         files ${SO_NAME}/" /etc/nsswitch.conf

id $TEST_USERNAME > /tmp/.output 2>&1

if [[ $? -eq "0" ]]
then
  echo -e "[✅] [ $OS_VER ]  GLIBC Version: $GLIBC_VER Test Passed"
  echo "[✅] [ $OS_VER ] Test Result: `cat /tmp/.output`"
  # exit 0
  service rsyslog start
  /usr/sbin/sshd -D
else
  echo -e "[❌] [ $OS_VER ]  GLIBC Version: $GLIBC_VER Test Failed"
  echo "Error Info: `cat /tmp/.output`"
  echo " - ldd /lib/libnss_${SO_NAME}.so.2"
  ldd /lib/libnss_${SO_NAME}.so.2
  echo " - cat /etc/nsswitch.conf | grep ${SO_NAME}"
  cat /etc/nsswitch.conf | grep ${SO_NAME}
  exit 1
fi
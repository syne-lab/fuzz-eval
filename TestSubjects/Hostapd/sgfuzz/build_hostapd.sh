#!/bin/bash

rm -rf TEST
cp -r seeds TEST

rm -rf hostapd-2.9

tar zxvf hostapd-2.9.tar.gz

cp test-harness.c hostapd-2.9/hostapd/main.c
cp Makefile.modified hostapd-2.9/hostapd/Makefile

cd hostapd-2.9

echo "Instrumenting...."
python3.10 /SGFuzz/sanitizer/State_machine_instrument.py ./ -b /target/blocked_hostapd
echo "Instrumenting....Done"
sleep 3

cat > hostapd/.config << "EOF"
CONFIG_BACKEND=file
CONFIG_CTRL_IFACE=y
CONFIG_DEBUG_FILE=y
CONFIG_DEBUG_SYSLOG=y
CONFIG_DEBUG_SYSLOG_FACILITY=LOG_DAEMON
CONFIG_DRIVER_NL80211=y
CONFIG_DRIVER_WEXT=y
CONFIG_DRIVER_WIRED=y
CONFIG_EAP_GTC=y
CONFIG_EAP_LEAP=y
CONFIG_EAP_MD5=y
CONFIG_EAP_MSCHAPV2=y
CONFIG_EAP_OTP=y
CONFIG_EAP_PEAP=y
CONFIG_EAP_TLS=y
CONFIG_EAP_TTLS=y
CONFIG_IEEE8021X_EAPOL=y
CONFIG_IPV6=y
CONFIG_LIBNL32=y
CONFIG_PEERKEY=y
CONFIG_PKCS12=y
CONFIG_READLINE=y
CONFIG_SMARTCARD=y
CONFIG_WPS=y
CONFIG_TLS=internal
CONFIG_INTERNAL_LIBTOMMATH=y
CFLAGS += -I/usr/include/libnl3
EOF

cd hostapd

make

cd ../..

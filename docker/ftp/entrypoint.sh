#!/bin/sh
# vsftpd baslaticisi.
#
# pasv_address artik Dockerfile'a sabit kodlu DEGIL — calisma aninda
# FTP_PASV_ADDRESS ortam degiskeninden okunur:
#   * deger verilirse  -> pasif mod o adresi ilan eder (eski PASV istemcileri icin)
#   * bos birakilirsa  -> vsftpd kontrol baglantisinin yerel adresini kullanir.
#                         EPSV (modern istemciler / Windows ftp.exe) zaten
#                         pasv_address'e bakmaz, oldugu gibi calisir.
set -e

CONF=/etc/vsftpd/vsftpd.conf

if [ -n "${FTP_PASV_ADDRESS}" ]; then
    echo "pasv_address=${FTP_PASV_ADDRESS}" >> "$CONF"
    echo "pasv_addr_resolve=NO"             >> "$CONF"
    echo "[ftp-entrypoint] pasv_address=${FTP_PASV_ADDRESS} ayarlandi"
else
    echo "[ftp-entrypoint] FTP_PASV_ADDRESS bos — pasif adres otomatik (EPSV onerilir)"
fi

exec /usr/sbin/vsftpd "$CONF"

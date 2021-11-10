#!/usr/bin/env python3

'''Source code ini menggunakan referensi dari buku Black Hat Python 2nd Edition yang dapat diakses di: https://www.peril.group/wp-content/uploads/2021/05/Black-Hat-Python-2nd-Edition.pdf '''

import socket
import ipaddress
import struct
import os
import sys

#modul ini akan digunakan untuk menampung informasi IP Header (decode)
#mendefinisikan IP class
class IP:
    def __init__(self, buff=None):
        #disini kita tentukan struktur format karakter yang akan kita gunakan
        #kita akan menggunakan format B (1 byte unsigned char)
        #H (2 byte unsigned short)
        #s (byte array), misal: 4s -> 4-byte string
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
        
        #menentukan ip address
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        
        #menyesuaikan protokol
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))

#modul ini digunakan untuk melakukan proses sniffing        
def sniff(host):
    #membuat raw socket dan melakukan binding ke interface
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    #promiscuous mode akan dinyalakan (hanya jika source code ini dijalankan pada sistem operasi windows)
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket. RCVALL_ON)
    
    try:
        while True:
            #melakukan proses pembacaan packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            #menyusun IP Header dari 20 byte pertama
            ip_header = IP(raw_buffer[0:20])
            #menampilkan host dan protokol yang terdeteksi
            print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    except KeyboardInterrupt:
        #promiscuous mode akan dimatikan (hanya jika source code ini dijalankan pada sistem operasi windows)
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sys.exit()
            
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '127.0.0.1'
    sniff(host)
#!/usr/bin/env python3

'''Source code ini menggunakan referensi dari  
https://www.peril.group/wp-content/uploads/2021/05/Black-Hat-Python-2nd-Edition.pdf dan 
dari channel YouTube Elevate Cyber dalam playlist Blackhat Python
part 1 --> https://www.youtube.com/watch?v=D9UvxHYChD8
part 2 --> https://www.youtube.com/watch?v=uqL3g8m8gJw'''

import sys
import socket
import threading

#Filter ini digunakan untuk menentukan apakah informasi/pesan yang masuk mengandung
#printable characters atau tidak
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

#Fungsi ini berguna untuk menampilkan detail packet pada proses pengiriman informasi/pesan
#dalam bentuk heksadesimal dan ASCII
def hexdump(src, length = 16, show = True):
	if isinstance(src, bytes):
		src = src.decode()
	results = list()
	for i in range(0, len(src), length):
		word = str(src[i:i+length])

		printable = word.translate(HEX_FILTER)
		hexa = ' '.join([f'{ord(c):02X}' for c in word])
		hexwidth = length*3
		results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
	if show:
		for line in results:
			print(line)
	else:
		return results

#Fungsi untuk menerima informasi/pesan yang masuk selama komunikasi
def receive_from(connection):
	#empty byte string untuk mengumpulkan informasi yang diterima
	buffer = b""

	connection.settimeout(5)
	try:
		while True:
			#membaca informasi yang masuk
			data = connection.recv(4096)
			if not data:
				break
			buffer += data
	except Exception as e:
		pass
	return buffer

#Kedua fungsi ini dapat digunakan untuk memodifikasi packet
def request_handler(buffer):
	return buffer

def response_handler(buffer):
	return buffer

#Fungsi ini berfungsi dalam mengatur laju arah komunikasi antara local dan remote machine
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#connect ke remote host
	remote_socket.connect((remote_host, remote_port))

	if receive_first:
		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)
	remote_buffer = response_handler(remote_buffer)
	if len(remote_buffer):
		print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
		client_socket.send(remote_buffer)

	while True:
		local_buffer = receive_from(client_socket)
		if len(local_buffer):
			line = "[==>] Received %d bytes from localhost." % len(local_buffer)
			print(line)
			hexdump(local_buffer)

			local_buffer = request_handler(local_buffer)
			remote_socket.send(local_buffer)
			print("[==>] Send to remote.")

		remote_buffer = receive_from(remote_socket)
		if len(remote_buffer):
			print("[<==] Received %d bytes from remote." % len(remote_buffer))
			hexdump(remote_buffer)

			remote_buffer = response_handler(remote_buffer)
			client_socket.send(remote_buffer)
			print("[<==] Sent to localhost.")

		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close()
			remote_socket.close()
			print("[*] No more data. Closing connections.")
			break

#Melakukan setup koneksi
def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		server.bind((local_host, local_port))
	except Exception as e:
		print("problem on bind: %r" %e)
		print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
		print("[!!] Check for other listening sockets or correct permissions.")
		sys.exit(0)

	print("[*] Listening on %s:%d" % (local_host, local_port))
	server.listen(5)

	while True:
		client_socket, addr = server.accept()
		#menampilkan informasi koneksi yang masuk
		line = "> Received incoming connection from %s:%d" % (addr[0], addr[1])
		print(line)
		#memulai thread untuk berkomunikasi dengan remote host

		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
		proxy_thread.start()

#Fungsi main
def main():
	if len(sys.argv[1:]) != 5:
		print("Usage: ./proxy1.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
		print("Example: ./proxy1.py 127.0.0.1 54321 127.0.0.1 54321 True")
		sys.exit(0)

	local_host = sys.argv[1]
	local_port = int(sys.argv[2])
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])
	receive_first = sys.argv[5]

	if "True" in receive_first:
		receive_first = True
	else:
		receive_first = False

	server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
	main()

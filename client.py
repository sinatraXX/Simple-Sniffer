#!/usr/bin/env python3

''' Source code ini menggunakan referensi dari https://realpython.com/python-sockets/
dan https://medium.com/python-pandemonium/python-socket-communication-e10b39225a4c '''

import socket

#Mendeklarasikan host dan port number Server (local)
HOST = '127.0.0.1'
PORT = 54321
SERVER_ADDRESS = (HOST, PORT)

#Membuat socket TCP/IP untuk Client
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

	#Menyambungkan socket Client pada Server
	print('Memulai koneksi pada {} di port {}'.format(*SERVER_ADDRESS))
	s.connect(SERVER_ADDRESS)

	try:

		#Mengirim pesan kepada Server
		message = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec id augue varius, efficitur lectus non, interdum dui. Morbi aliquet maximus nisl ac suscipit. Nulla egestas massa ac ullamcorper ultricies. Pellentesque tristique maximus ante, quis vulputate metus pretium et. Aliquam pulvinar, nulla nec egestas suscipit, ante ante vulputate ipsum, ac rutrum odio eros at justo. Phasellus elementum sem et lectus accumsan, sit amet varius felis hendrerit. Donec volutpat lobortis sapien, vitae ullamcorper leo accumsan non. Nullam eleifend nulla id massa condimentum, quis malesuada neque viverra. Cras ut urna sit amet diam iaculis interdum id a risus. Quisque laoreet nunc eget lorem maximus, a elementum nisl tempus. Donec eget mi sit amet mauris hendrerit tincidunt. '
		print('mengirim {!r}'.format(message))
		s.sendall(message)

		#Mencari respon dari Server
		amount_received = 0
		amount_expected = len(message)

		while amount_received < amount_expected:
			pesan = s.recv(16)
			amount_received += len(pesan)
			print('menerima {!r}'.format(pesan))

	finally:
		#Memberhentikan koneksi
		print('Koneksi selesai.')
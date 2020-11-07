from utils import *
from hashlib import sha1
from sys import argv
from socket import socket
from Crypto.Random import get_random_bytes

if len(argv) < 3:
	print("Mod de utilizare:", argv[0], "<ip:port pentru bind si listen> <parola din care va fi derivata K3>")
	exit()

ip, port = argv[1].split(":")

# obtin cheia K3 dintr-un sha1 pe o parola
K3 = sha1(argv[2].encode('utf-8')).digest()[:16]

def key_send_handler(client, ip_port):
	ip_port = ip_port[0] + ":" + str(ip_port[1])
	print("[server -- info] New client", ip_port)
	key_type = client.recv(3)
	if key_type == b"ECB":
		client.send(aes_encrypt_block(get_random_bytes(16), K3))
		print("["+ip_port+" -- info] Client asked for the ECB key")
	elif key_type == b"CFB":
		client.send(aes_encrypt_block(get_random_bytes(16), K3))
		print("["+ip_port+" -- info] Client asked for the CFB key")
	else:
		client.send(aes_encrypt_block(get_random_bytes(16), K3))
		print("["+ip_port+" -- info] Client asked for a random key")
	client.close()

try:
	create_server(ip, port, key_send_handler)
except Exception as e:
	print("[!!!] Server is closing")
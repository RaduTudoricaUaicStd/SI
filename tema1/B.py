from utils import *
from hashlib import sha1
from sys import argv, stdout, stderr
from socket import socket

if len(argv) < 3:
	print("Mod de utilizare:", argv[0], "<ip:port pentru bind si listen> <parola din care va fi derivata K3>")
	exit()

ip, port = argv[1].split(":")
# obtin cheia K3 dintr-un sha1 pe o parola
K3 = sha1(argv[2].encode('utf-8')).digest()[:16]
IV = b"0123456789ABCDEF"

def receive_file_handler(client, ip_port):
	ip_port = ip_port[0] + ":" + str(ip_port[1])
	print("[server -- info] New client", ip_port, file = stderr)
	key_type = client.recv(3)
	key = aes_decrypt_block(client.recv(16), K3)
	print("["+ip_port+" -- info] Decrypted key", file = stderr)
	proof = aes_encrypt_block(sha1(key).digest()[:16], K3)
	decryptor = None
	if key_type == b"ECB":
		print("["+ip_port+" -- info] Client uses ECB", file = stderr)
		decryptor = aes_ecb_decrypt(iter( lambda: client.recv(16), b'' ), key)
	elif key_type == b"CFB":
		print("["+ip_port+" -- info] Client uses CFB", file = stderr)
		decryptor = aes_cfb_decrypt(iter( lambda: client.recv(16), b'' ), key, IV)
	else:
		print("["+ip_port+" -- info] Unknown mode, defaulting to CFB", file = stderr)
		decryptor = aes_cfb_decrypt(iter( lambda: client.recv(16), b'' ), key, IV)

	print("["+ip_port+" -- info] Finishing the handshake by sending the proof that i know the key", file = stderr)
	client.send(proof)
	print("["+ip_port+" -- info] Reading the file to stdout", file = stderr)
	for block in decryptor:
		stdout.buffer.write(block)

	stdout.flush()
	client.close()

try:
	create_server(ip, port, receive_file_handler)
except Exception as e:
	print("[!!!] Server is closing", file = stderr)
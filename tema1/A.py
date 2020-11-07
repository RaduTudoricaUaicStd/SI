from utils import *
from hashlib import sha1
from sys import argv, stdout, stderr
from socket import socket

if len(argv) < 6:
	print("Mod de utilizare:", argv[0], "<ip:port pentru KM> <ip:port pentru B> <parola din care va fi derivata K3> <modul de comunicare> <fisierul care va fi trimis>")
	exit()

KM_addr = argv[1].split(":")
B_addr = argv[2].split(":")
# obtin cheia K3 dintr-un sha1 pe o parola
K3 = sha1(argv[3].encode('utf-8')).digest()[:16]
IV = b"0123456789ABCDEF"

try:
	print("[*] Connecting to KM")
	KM = socket()
	KM.connect((KM_addr[0], int(KM_addr[1])))
except:
	print("[!] Counld not connect to node KM")
	exit()

try:
	print("[*] Connecting to B")
	B = socket()
	B.connect((B_addr[0], int(B_addr[1])))
except:
	print("[!] Counld not connect to node B")
	exit()

print("[*] Sending to B and KM the mode of operation")
B.send(argv[4].encode("utf-8")[:3])
KM.send(argv[4].encode("utf-8")[:3])

encrypted_key = KM.recv(16)
print("[*] Received the encrypted key, sending it to node B")
B.send(encrypted_key)
key = aes_decrypt_block(encrypted_key, K3)

try:
	assert aes_decrypt_block(B.recv(16), K3) == sha1(key).digest()[:16]
	print("[*] Node B passed the K3 knowing proof, sending the file now")
except:
	print("[!] Node B doesn't know K3, exiting")
	exit()

file = open(argv[5], 'rb')
if argv[4] == "ECB":
	encryptor = aes_ecb_encrypt(iter( lambda: file.read(16), b'' ), key)
elif argv[4] == "CFB":
	encryptor = aes_cfb_encrypt(iter( lambda: file.read(16), b'' ), key, IV)
else:
	encryptor = aes_cfb_encrypt(iter( lambda: file.read(16), b'' ), key, IV)

for block in encryptor:
	B.send(block)
B.close()
file.close()
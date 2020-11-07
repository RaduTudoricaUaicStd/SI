from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from threading import Thread
from socket import socket
from math import ceil
from sys import stderr

# functiile pad si unpad sunt utilizate pentru date nealiniate la blocksize-ul necesar folosind schema PKCS5
# in sine pad[i] = to_byte(size_of_needed_bytes)
#
# ex: block_size = 8, text_size = 5, text = b"abcde"
# rezultat = b"abcde" + b"\x03\x03\x03"

def pad(data, block_size = 16):
	pad_size = block_size - ( len(data)  % block_size )
	if pad_size == 0:
		return data
	return data + bytes([pad_size]) * pad_size

def unpad(data, block_size = 16):
	pad_size = data[-1]
	padding_bytes = bytes([pad_size]) * pad_size
	if pad_size == 0 or pad_size >= block_size or padding_bytes != data[-pad_size:]:
		return data
	return data[:-pad_size]

# functiile aes_encrypt_block si aes_decrypt_block sunt folosite pentru criptarea si decriptarea unui bloc ajustat la lungimea corecta
# este initializat cu modul ECB pentru ca nu ma lasa libraria fara sa folosesc un mod de operare
# (nu ma lasa sa fiu prost si ma pune sa aleg un mod de operare convenabil scenariului meu)
# iar un bloc de ECB e doar AES aplicat pe un bloc de date

def aes_encrypt_block(data, key):
	if len(data) < 16:
		data = pad(data)
	return AES.new(key = key, mode = AES.MODE_ECB).encrypt(data)

def aes_decrypt_block(data, key):
	return unpad(AES.new(key = key, mode = AES.MODE_ECB).decrypt(data))

def test_aes_block_encryption():
	key = get_random_bytes(16)
	text = b"ana are mere"
	etext = aes_encrypt_block(text, key)
	print("Original:", text)
	print("Dupa criptare:", etext)
	print("Dupa decriptare:", aes_decrypt_block(etext, key))
	assert aes_decrypt_block(etext, key) == text



# functiile yield_blocks si xor sunt pur ajutatoare


# yield_blocks face yield la fiecare bloc, impare inputul daca este de tip bytes in blocuri
# daca nu, considera ca deja datele sunt impartite in blocuri si itereaza peste ele
# metoda de iterare este folosita pentru a putea citi si decripta block cu block fara sa citesc toate datele in memorie in acelasi timp

def yield_blocks(data, block_size):
	if type(data) == bytes:
		for block_number in range(ceil(len(data)/block_size)):
			yield data[block_size * block_number : block_size * block_number + block_size]
	else:
		for block in data:
			yield block

# functia xor doar face xor intre obiectele iterabile X si Y, se opreste cand unul din ele nu mai are date

def xor(X, Y):
	return bytes([ x^y for x,y in zip(X, Y) ])


# o implementare generica a modului ECB

# pentru i >= 0
# ciphertext[i] = function(plaintext[i], key)
# plaintext[i] = reverse_function(ciphertext[i], key)

def ecb_mode_generic(function, block_size, key, data):
	for block in yield_blocks(data, block_size):
		yield function(block, key)

# o implementare generica a modului CFB

# pentru i > 0
# ciphertext[i] = plaintext[i] ^ function(ciphertext[i - 1], key)
# plaintext[i] = ciphertext[i] ^ function(ciphertext[i - 1], key)

# si pentru   i == 0
# ciphertext[0] = plaintext[0] ^ function(IV, key)
# plaintext[0] = ciphertext[0] ^ function(IV, key)

def cfb_mode_generic(function, block_size, key, data, iv_update, IV):
	for block in yield_blocks(data, block_size):
		result = xor(block, function(IV, key))
		IV = iv_update(block, result)
		yield result[:len(block)]


# specializarile algoritmilor
def aes_ecb_encrypt(data, key):
	return ecb_mode_generic(aes_encrypt_block, 16, key, data)

def aes_ecb_decrypt(data, key):
	return ecb_mode_generic(aes_decrypt_block, 16, key, data)

def aes_cfb_encrypt(data, key, IV):
	return cfb_mode_generic(aes_encrypt_block, 16, key, data, lambda block, result: result, IV)

def aes_cfb_decrypt(data, key, IV):
	return cfb_mode_generic(aes_encrypt_block, 16, key, data, lambda block, result: block, IV)

def test_aes_modes_encryption():
	key = get_random_bytes(16)
	IV = get_random_bytes(16)
	text = b"ana are mere   "*3
	print(text, len(text))

	ecb_enc = list(aes_ecb_encrypt(text, key))
	cfb_enc = list(aes_cfb_encrypt(text, key, IV))
	print("ECB:", b"".join(ecb_enc), len(b"".join(ecb_enc)))
	print("CFB:", b"".join(cfb_enc), len(b"".join(cfb_enc)))
	print("ECB blocks:", ecb_enc)
	print("CFB blocks:", cfb_enc)
	print("ECB-D:", aes_ecb_decrypt(ecb_enc, key))
	print("CFB-D:", aes_cfb_decrypt(cfb_enc, key, IV))
	assert b"".join(list(aes_ecb_decrypt(ecb_enc, key))) == text
	assert b"".join(aes_cfb_decrypt(cfb_enc, key, IV)) == text


# functii ajutatoare pentru partea de server

# creeaza un nou thread daemon
def start_daemon_thread(target, args = tuple()):
	thread = Thread(target = target, args = args)
	thread.daemon = True
	thread.start()

# creeaza un nou server care apeleaza functia handler_function intr-un thread daemon la fiecare noua conexiune
def create_server(ip, port, handler_function):
	server = socket()
	server.bind((ip, int(port)))
	server.listen(5)
	print("[server -- info] Server is listening on", ip, ":", port, file = stderr)

	while True:
		client, client_ip_port = server.accept()
		start_daemon_thread(handler_function, (client, client_ip_port))


if __name__ == '__main__':
	test_aes_modes_encryption()
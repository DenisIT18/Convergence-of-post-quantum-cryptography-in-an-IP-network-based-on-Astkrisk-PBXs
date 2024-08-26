import socket
import ssl
import ipaddress
from docopt import docopt
from ntru.ntrucipher import NtruCipher # type: ignore
from ntru.mathutils import random_poly # type: ignore
from sympy.abc import x
from sympy import ZZ, Poly
from padding.padding import * # type: ignore
import numpy as np
import sys
import logging
import math

log = logging.getLogger("ntru")

debug = False
verbose = False


def generate(N, p, q, priv_key_file, pub_key_file):
    ntru = NtruCipher(N, p, q)
    ntru.generate_random_keys()
    h = np.array(ntru.h_poly.all_coeffs()[::-1])
    f, f_p = ntru.f_poly.all_coeffs()[::-1], ntru.f_p_poly.all_coeffs()[::-1]
    np.savez_compressed(priv_key_file, N=N, p=p, q=q, f=f, f_p=f_p)
    log.info("Private key saved to {} file".format(priv_key_file))
    np.savez_compressed(pub_key_file, N=N, p=p, q=q, h=h)
    log.info("Public key saved to {} file".format(pub_key_file))


def encrypt(pub_key_file, input_arr, bin_output=False, block=False):
    pub_key = np.load(pub_key_file, allow_pickle=True)
    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']))
    ntru.h_poly = Poly(pub_key['h'].astype(np.int)[::-1], x).set_domain(ZZ)
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        output = (ntru.encrypt(Poly(input_arr[::-1], x).set_domain(ZZ),
                               random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
    else:
        input_arr = padding_encode(input_arr, ntru.N) # type: ignore
        input_arr = input_arr.reshape((-1, ntru.N))
        output = np.array([])
        block_count = input_arr.shape[0]
        for i, b in enumerate(input_arr, start=1):
            log.info("Processing block {} out of {}".format(i, block_count))
            next_output = (ntru.encrypt(Poly(b[::-1], x).set_domain(ZZ),
                                        random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
            if len(next_output) < ntru.N:
                next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
            output = np.concatenate((output, next_output))

    if bin_output:
        k = int(math.log2(ntru.q))
        output = [[0 if c == '0' else 1 for c in np.binary_repr(n, width=k)] for n in output]
    return np.array(output).flatten()


def decrypt(priv_key_file, input_arr, bin_input=False, block=False):
    priv_key = np.load(priv_key_file, allow_pickle=True)
    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']))
    ntru.f_poly = Poly(priv_key['f'].astype(np.int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(np.int)[::-1], x).set_domain(ZZ)

    if bin_input:
        k = int(math.log2(ntru.q))
        pad = k - len(input_arr) % k
        if pad == k:
            pad = 0
        input_arr = np.array([int("".join(n.astype(str)), 2) for n in
                              np.pad(np.array(input_arr), (0, pad), 'constant').reshape((-1, k))])
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
        return ntru.decrypt(Poly(input_arr[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]

    input_arr = input_arr.reshape((-1, ntru.N))
    output = np.array([])
    block_count = input_arr.shape[0]
    for i, b in enumerate(input_arr, start=1):
        log.info("Processing block {} out of {}".format(i, block_count))
        next_output = ntru.decrypt(Poly(b[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]
        if len(next_output) < ntru.N:
            next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
        output = np.concatenate((output, next_output))
    return padding_decode(output, ntru.N) # type: ignore

# Обработчик клиента
def handle_client(client_socket, client_address, priv_key_file, pub_key_file):
    try:
        print(f"Connection established from {client_address}")

        with client_socket:
            ssl_socket = context.wrap_socket(client_socket, server_side=True)

            # Read all data from the client
            received_data = b''
            while True:
                data = ssl_socket.recv(4096)
                if not data:
                    break
                received_data += data

            print(f"Received: {received_data.decode('utf-8')}")

            # Decrypt received data
            decrypted_data = decrypt(priv_key_file, received_data)

            # Process decrypted data (if needed)
            processed_data = processed_data(decrypted_data)

            # Encrypt response
            encrypted_response = encrypt(pub_key_file, processed_data)

            # Send encrypted response to the client
            ssl_socket.sendall(encrypted_response)
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Инициализация контекста SSL
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

# Загрузка сертификата SSL и закрытого ключа
context.load_cert_chain('/path/to/certchain.pem', '/path/to/private.key')

# Пути к файлам с ключами
PRIV_KEY_FILE = 'path/to/priv_key.npz'
PUB_KEY_FILE = 'path/to/pub_key.npz'

# Создание сокета
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    try:
        server_socket.bind(('127.0.0.1', 8080))  # Привязка к нужному адресу и порту
        server_socket.listen(5)  # Ожидание входящих соединений

        print("Server is listening...")

        while True:
            # Принятие соединений от клиентов
            client_socket, client_address = server_socket.accept()
            handle_client(client_socket, client_address)
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Ввод IP-адресов (отправителя и получателя)
source_IP_address = ipaddress.IPv4Address(input("Введите IP-адрес отправителя: "))
destination_IP_address = ipaddress.IPv4Address(input("Введите IP-адрес получателя: "))

source_IP_address_v6 = ipaddress.IPv6Address(input("Введите IP-адрес отправителя: "))
destination_IP_address_v6 = ipaddress.IPv6Address(input("Введите IP-адрес получателя: "))
print(source_IP_address)
print(destination_IP_address)

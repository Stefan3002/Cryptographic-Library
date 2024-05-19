import math
import time

import gmpy2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

READ_SIZE = 16
def read_public_key(path):
    '''
    Function to read a public key from a file
    :param path: Path to the file containing the public key
    :return: Tuple with the public key (e, n)
    '''
    with open(path, "rb") as f:
        pem_data = f.read()
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        return (e, n)

def read_private_key(path, password=None):
    '''
    Function to read a private key from a file
    :param path: Path to the file containing the private key
    :param password: Password to decrypt the private key
    :return: Tuple with the private key (d, n)
    '''
    with open(path, "rb") as f:
        pem_data = f.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

        private_numbers = private_key.private_numbers()

        d = private_numbers.d
        p = private_numbers.p
        q = private_numbers.q

        return (d, p * q)

def encrypt(public_key, plaintext, type='message', out_file='encrypted_file'):
    '''
    Function to encrypt a message using a public key
    :param public_key: Tuple with the public key (e, n)
    :param plaintext: Message to be encrypted
    :return: None
    '''

    start_time = time.time()
    total_bytes = 0
    print('Started the encryption...')

    # Unpack the key
    key, n = public_key
    # see on how many bytes you should write the encrypted bytes so that they do not overflow and
    # also you do not use more bytes than necessary
    n_bit_size = n.bit_length()
    # Calculate the byte size required for each encrypted integer
    byte_size = math.ceil(n_bit_size / 8)

    if type == 'message':
        # Apply: c = m^e mod n
        cipher = [gmpy2.powmod(ord(char), key, n) for char in plaintext]
    elif type == 'file':
        with open(out_file, 'wb') as out:
            with open(plaintext, 'rb') as f:
                data = f.read(READ_SIZE)
                while data:
                    total_bytes += READ_SIZE
                    # When traversing some bytes, you actually get them as integers
                    cipher = [gmpy2.powmod(byte, key, n) for byte in data]
                    # For every encrypted byte, write it to the output file (as a byte, not as an integer
                    for c in cipher:
                        out.write(int(c).to_bytes(byte_size, byteorder='big'))
                    data = f.read(READ_SIZE)
    end_time = time.time()
    print(f'Successfully encrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds \n')
    print(f'The encryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')






def decrypt(private_key, ciphertext, type='message', out_file='decrypted_file'):
    '''
    Function to decrypt a message using a private key
    :param private_key: Tuple with the private key (d, n)
    :param ciphertext: List with the encrypted message (containing numbers)
    :return: Decrypted message
    '''

    start_time = time.time()
    total_bytes = 0
    print('Started the decryption...')

    # Unpack the key
    key, n = private_key

    # see on how many bytes you should write the encrypted bytes so that they do not overflow and
    # also you do not use more bytes than necessary
    n_bit_size = n.bit_length()
    # Calculate the byte size required for each encrypted integer
    byte_size = math.ceil(n_bit_size / 8)

    if type == 'message':
    # Apply: m = c^d mod n
        plain = [chr(int(gmpy2.powmod(char, key, n))) for char in ciphertext]
    elif type == 'file':
        with open(out_file, 'wb') as out:
            with open(ciphertext, 'rb') as f:
                data = f.read(byte_size)
                while data:
                    # We only read ONE (old, decrypted) byte (but it was written on byte_size bytes in its encrypted form)
                    byte = int.from_bytes(data, byteorder='big')
                    plain = gmpy2.powmod(byte, key, n)
                    # Write the decrypted byte to the output file (remember, it is just ONE byte)
                    out.write(int(plain).to_bytes(1, byteorder='big'))
                    total_bytes += 1
                    data = f.read(byte_size)
    end_time = time.time()
    print(f'Successfully encrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds \n')
    print(f'The encryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')
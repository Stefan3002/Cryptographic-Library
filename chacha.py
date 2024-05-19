import math
import time

# https://datatracker.ietf.org/doc/html/rfc7539
CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
def quarter_round(a, b, c, d):
    '''
    A function that performs the quarter round operation on 4 numbers
    :param a: The first number of the quarter round
    :param b: The second number of the quarter round
    :param c: The third number of the quarter round
    :param d: The fourth number of the quarter round
    :return: The 4 modified numbers after the quarter round operation
    '''
    # 0xFFFFFFFF is essentially a 32 bit number that is made only of 1s
    # It is used to prevent the number from overflowing the 32 bits
    # C language would truncate the overflowing value to fit in the 32 bit window
    # Python would NOT!, it would grow to a 64 bit number.
    # According to RFC 8439 we only want 32 bits
    a = (a + b) & 0xFFFFFFFF
    d = (d ^ a) & 0xFFFFFFFF
    # RFC says d <<<= 16;
    # The shift left (<<) does not rotate the bits, it just shifts them to the left
    # The shift right (>>) does not rotate the bits, it just shifts them to the right
    # The OR operator (|) is used to concatenate the bits that would normally fall of the side on the left shift.
    # We shifted them to the right and added them to the result
    # Thus simulating a rotation
    d = (d << 16 | d >> 16) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = (b ^ c)
    b = (b << 12 | b >> 20) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d = (d ^ a)
    d = (d << 8 | d >> 24) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = (b ^ c)
    b = (b << 7 | b >> 25) & 0xFFFFFFFF
    return a, b, c, d


def QUARTERROUND(a, b, c, d, chacha_state):
    '''
    A function that performs the quarter round operation on the chacha state matrix
    :param a: First number
    :param b: Second number
    :param c: Third number
    :param d: Fourth number
    :param chacha_state: The current matrix state of the chacha algorithm
    :return: The modified chacha state matrix after the quarter round
    '''
    new_a, new_b, new_c, new_d = quarter_round(chacha_state[a], chacha_state[b], chacha_state[c], chacha_state[d])
    chacha_state[a] = new_a
    chacha_state[b] = new_b
    chacha_state[c] = new_c
    chacha_state[d] = new_d
    return chacha_state


def print_chacha_state(chacha_state):
    '''
    Utility function that prints the chacha state matrix in hexadecimal format
    :param chacha_state: The state of the chacha algorithm
    :return: Void
    '''
    for i in chacha_state:
        print(hex(i))




def chacha_block_round(chacha_state):
    '''
    A function that performs the chacha block round operation on the chacha state matrix. It consists of both column and diagonal quarterounds
    :param chacha_state: The current matrix state of the chacha algorithm
    :return: Void
    '''
    # For one round
    # Column rounds
    QUARTERROUND(0, 4, 8, 12, chacha_state)
    QUARTERROUND(1, 5, 9, 13, chacha_state)
    QUARTERROUND(2, 6, 10, 14, chacha_state)
    QUARTERROUND(3, 7, 11, 15, chacha_state)
    # Diagonal rounds
    QUARTERROUND(0, 5, 10, 15, chacha_state)
    QUARTERROUND(1, 6, 11, 12, chacha_state)
    QUARTERROUND(2, 7, 8, 13, chacha_state)
    QUARTERROUND(3, 4, 9, 14, chacha_state)


def prepare_key(key):
    '''
    Utility function that prepares the key for the chacha algorithm. It converts the key from hexadecimal to bytes
    It then groups the bytes into groups of 4 and converts them into little-endian integers
    E.g: 00010203 -> 0x03020100 -> 50462976
    :param key: The key in hexadecimal format
    :return: The key as an array of integers (that are groups of 4 bytes in little-endian taken from the original hexadecimal key)
    '''
    # Convert the hex key into bytes
    key = bytes.fromhex(key)
    # Group the bytes into groups of 4
    little_endian_key = [key[i:i + 4][::-1] for i in range(0, len(key), 4)]
    # Convert them into ints while also reversing them via byteorder
    int_key = [int.from_bytes(group, byteorder='big') for group in little_endian_key]
    return int_key


def chacha_block(key, counter, nonce):
    '''
    A function that performs the chacha block operation on the chacha algorithm. It consists of 20 rounds of quarter rounds
    :param key: The key for the chacha algorithm (as an array of integers)
    :param counter: The counter for the chacha algorithm
    :param nonce: The nonce for the chacha algorithm (as an array of integers)
    :return: The serialized state of the chacha algorithm after 20 rounds (also called the key stream)
    '''
    # Put the counter into an array tobe able to concatenate it easily to the state
    counter = [counter]
    # Create the state according to the RFC
    state = CONSTANTS + key + counter + nonce
    # Make a deep copy of the state as we need to add it at the end of the
    # 20 rounds
    initial_state = state[:]
    for i in range(0, 10):
        chacha_block_round(state)
    # According to RFC
    # At the end of 20 rounds (or 10 iterations of the above list), we add
    # the original input words to the output words, and serialize the
    # result by sequencing the words one-by-one in little-endian order.
    for i in range(0, len(state)):
        # Make sure not to overflow 32 bits
        state[i] = (state[i] + initial_state[i]) & 0xFFFFFFFF
    # Take the hexadecimal values (that are actually represented as integers), group them into 4 bytes and reverse
    # their order (little-endian)
    serialized_state = [block.to_bytes(4, byteorder='little') for block in state]
    # Because the serialized_state is an array, just join the bytes
    return b''.join(i for i in serialized_state)


# ENCRYPT / DECRYPT
KEY_SIZE = 256

def chacha_encrypt_decrypt(key, counter, nonce, plaintext, mode='text'):
    '''
    A function that encrypts or decrypts the plaintext using the chacha algorithm
    :param key: The key for the chacha algorithm (as an array of integers)
    :param counter: The counter for the chacha algorithm
    :param nonce: The nonce for the chacha algorithm (as an array of integers)
    :param plaintext: The plaintext to be encrypted or the cypher text decrypted
    :param mode: Whether the plaintext is in text or bytes format ("text", "bytes")
    :return: The encrypted serialized bytes or the decrypted text (or serialized bytes)
    '''
    encrypted_block = b''
    if mode == 'text':
        plaintext = plaintext.encode()
    # Iterate over the text in blocks of 64 bits
    for j in range(0, math.floor(len(plaintext) / 64)):
        key_stream = chacha_block(key, counter + j, nonce)
        # Take the current block of input text of 64 bits
        text_block = plaintext[j * 64: j * 64 + 64]
        # XOR, but we need to manually iterate
        xor_res = bytes([a ^ b for a, b in zip(text_block, key_stream)])
        # Concatenate the result
        encrypted_block += xor_res
    # What if we are left with fewer than 64 bits
    if len(plaintext) % 64 != 0:
        j = math.floor(len(plaintext) / 64)
        key_stream = chacha_block(key, counter + j, nonce)
        text_block = plaintext[j * 64: len(plaintext)]
        xor_res = bytes([a ^ b for a, b in zip(text_block, key_stream)])
        encrypted_block += xor_res
    return encrypted_block

def encrypt_file(file_path, key, nonce, key_type='string', out_name='output-encrypted'):
    '''
    A function that encrypts the file using the chacha20 algorithm
    :param file_path: The path to the file to be encrypted
    :param key: The key for the chacha algorithm
    :param nonce: The nonce for the chacha algorithm
    :param out_name: The name of the output file
    :return: Void
    '''
    start_time = time.time()
    total_bytes = 0
    print('Started the encryption...')

    if key_type == 'file':
        print("Reading the key...")
        with open(key, 'r') as f:
            key = f.read(KEY_SIZE)
        print("Key read successfully")

    with open(file_path, 'rb') as f:
        print('Opened the input file...')
        with open(out_name, 'wb') as out_f:
            while True:
                # Read the bytes of the file
                plaintext = f.read(READ_SIZE)
                total_bytes += len(plaintext)
                # Check for EOF
                if not plaintext:
                    break
                int_key = prepare_key(key)
                int_nonce = prepare_key(nonce)
                # Start encrypting the bytes as you read them
                res = chacha_encrypt_decrypt(int_key, 1, int_nonce, plaintext, mode='bytes')
                # Write the encrypted bytes to the output file
                out_f.write(res)
    end_time = time.time()
    print(f'Successfully encrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds \n')
    print(f'The encryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')
# FILES - SUPPORT FUNCTIONS
READ_SIZE = 64
def decrypt_file(file_path, key, nonce, key_type='string', out_name='output-decrypted'):
    '''
    A function that decrypts the file using the chacha20 algorithm
    :param file_path: The path to the file to be decrypted
    :param key: The key for the chacha algorithm
    :param nonce: The nonce for the chacha algorithm
    :param out_name: The name of the output file
    :return: Void
    '''
    start_time = time.time()
    total_bytes = 0
    print('Started the decryption...')

    if key_type == 'file':
        print("Reading the key...")
        with open(key, 'r') as f:
            key = f.read(KEY_SIZE)
        print("Key read successfully")

    with open(file_path, 'rb') as f:
        print('Opened the input file...')
        with open(out_name, 'wb') as out_f:
            while True:
                # Read the bytes of the file
                plaintext = f.read(READ_SIZE)
                total_bytes += len(plaintext)
                # Check for EOF
                if not plaintext:
                    break
                int_key = prepare_key(key)
                int_nonce = prepare_key(nonce)
                # Start decrypting the bytes as you read them
                res = chacha_encrypt_decrypt(int_key, 1, int_nonce, plaintext, mode='bytes')
                # Write the decrypted bytes to the output file
                out_f.write(res)
    end_time = time.time()
    print(f'Successfully decrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds')
    print(f'The decryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')

# key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
# int_key = prepare_key(key)
# nonce = '000000000000004a00000000'
# int_nonce = prepare_key(nonce)
# res = chacha_encrypt_decrypt(int_key, 1, int_nonce, 'aloha')
# print(res)
# res = chacha_encrypt_decrypt(int_key, 1, int_nonce, res, mode='bytes')
# print(res)


# Initial chacha state
# cccccccc  cccccccc  cccccccc  cccccccc
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
# kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
# bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
# c=constant k=key b=blockcount n=nonce
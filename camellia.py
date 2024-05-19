# https://datatracker.ietf.org/doc/rfc3713/
import time

# Constant MASKS according to the RFC 3713
MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

# Initializing the subkeys according to RFC 3713
kw1 = kw2 = kw3 = kw4 = k1 = k2 = k3 = k4 = k5 = k6 = ke1 = ke2 = k7 = k8 = k9 = k10 = k11 = k12 = ke3 = ke4 = k13 = k14 = k15 = k16 = k17 = k18 = ke5 = ke6 = k19 = k20 = k21 = k22 = k23 = k24 = 0


# Constant SIGMAs according to the RFC 3713
Sigma1 = 0xA09E667F3BCC908B
Sigma2 = 0xB67AE8584CAA73B2
Sigma3 = 0xC6EF372FE94F82BE
Sigma4 = 0x54FF53A5F1D36F1C
Sigma5 = 0x10E527FADE682D1D
Sigma6 = 0xB05688C2B3E6C1FD

SBOX1_matrix = [
    [112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65],
    [35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189],
    [134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26],
    [166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77],
    [139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153],
    [223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215],
    [20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34],
    [254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80],
    [170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210],
    [16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148],
    [135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226],
    [82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46],
    [233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89],
    [120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250],
    [114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164],
    [64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158]
]
# To access items like in RFC 3713 (element 61 is referenced as 0x3D), we need to flatten the matrix
SBOX1 = [item for sublist in SBOX1_matrix for item in sublist]


def SBOX2(x):
    '''
    Function used to apply the SBOX2 to the given number. In RFC 3713, the SBOX2 is defined as a left rotation of 1 bit of the SBOX1 matrix.
    :param x: The element to be applied the SBOX2
    :return: The result of the SBOX2 applied to the given element
    '''
    return (SBOX1[x] << 1 | SBOX1[x] >> 7) & MASK8
def SBOX3(x):
    '''
    Function used to apply the SBOX3 to the given number. In RFC 3713, the SBOX3 is defined as a left rotation of 7 bits of the SBOX1 matrix.
    :param x: The element to be applied the SBOX3
    :return: The result of the SBOX3 applied to the given element
    '''
    return (SBOX1[x] << 7 | SBOX1[x] >> 1) & MASK8
def SBOX4(x):
    '''
    Function used to apply the SBOX4 to the given number. In RFC 3713, the SBOX4 is defined as a left rotation of 1 bit of the x and then return the SBOX1 matrix value in that x.
    :param x: The element to be applied the SBOX4
    :return: The result of the SBOX4 applied to the given element
    '''
    return SBOX1[(x << 1 | x >> 7) & MASK8] & MASK8

# Camellia can be divided into "key scheduling part" and "data randomizing part".
# We'll try to only do  the "key scheduling part" once per 16 bytes of data read from files.
# b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9
def prepare_key(key, type=128):
    '''
    Used to prepare the key for the encryption/decryption process
    :param key: The key to be used
    :param type: The number of bits that the given key has: 128, 192 or 256
    :return: KL and KR parts of the key
    '''
    if type == 128:
        return key, 0
    if type == 192:
        return key >> 64, (((key & MASK64) << 64) | (~(key & MASK64))) & MASK128
    elif type == 256:
        return key >> 128, key & MASK128
    else:
        return -1


def F(F_IN, KE):
    '''
    Function used to apply the F function to the given number
    :param F_IN: The number to be applied the F function
    :param KE: The key to be used in the F function
    :return: The result of the F function applied to the given number
    '''
    x = F_IN ^ KE
    t1 = x >> 56
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >> 8) & MASK8
    t8 = x & MASK8
    t1 = SBOX1[t1]
    t2 = SBOX2(t2)
    t3 = SBOX3(t3)
    t4 = SBOX4(t4)
    t5 = SBOX2(t5)
    t6 = SBOX3(t6)
    t7 = SBOX4(t7)
    t8 = SBOX1[t8]
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8
    return F_OUT

def FL(FL_IN, KE):
    '''
    Function used to apply the FL function to the given number
    :param FL_IN: The number to be applied the FL function
    :param KE: The key to be used in the FL function
    :return: The result of the FL function applied to the given number
    '''
    x1 = FL_IN >> 32
    x2 = FL_IN & MASK32
    k1 = KE >> 32
    k2 = KE & MASK32
    x2 = (x2 ^ ((x1 & k1) << 1 | (x1 & k1) >> 31)) & MASK32
    x1 = (x1 ^ (x2 | k2)) & MASK32
    FL_OUT = ((x1 << 32) | x2) & MASK64

    return FL_OUT


def FLINV(FLINV_IN, KE):
    '''
    Function used to apply the FLINV (inverse of FL) function to the given number
    :param FLINV_IN: The number to be applied the FLINV function
    :param KE: The key to be used in the FLINV function
    :return: The result of the FLINV function applied to the given number
    '''
    y1 = FLINV_IN >> 32
    y2 = FLINV_IN & MASK32
    k1 = KE >> 32
    k2 = KE & MASK32
    y1 = (y1 ^ (y2 | k2)) & MASK32
    y2 = (y2 ^ ((y1 & k1) << 1 | (y1 & k1) >> 31)) & MASK32
    # The mask here is just a safe guard, the number SHOULD have 64 bits, so the mask is useless, but still, better safe than sorry!
    FLINV_OUT = ((y1 << 32) | y2) & MASK64

    return FLINV_OUT

def generate_128bit_subkeys(KL, KA):
    '''
    Function used to generate the subkeys for the 128-bit keys: kw1, ..., kw4, k1, ..., k18, ke1, ..., ke4
    :param KL: The left part of the key
    :param KA: The right part of the key
    :return: None
    '''
    global kw1, kw2, kw3, kw4, k1, k2, k3, k4, k5, k6, ke1, ke2, k7, k8, k9, k10, k11, k12, ke3, ke4, k13, k14, k15, k16, k17, k18
    # KL has 128 bits
    # KA has 128 bits
    kw1 = (((KL << 0 | KL >> 128) & MASK128) >> 64) & MASK64
    kw2 = (((KL << 0 | KL >> 128) & MASK128) & MASK64)
    k1 = (((KA << 0 | KA >> 128) & MASK128) >> 64) & MASK64
    k2 = (((KA << 0 | KA >> 128) & MASK128) & MASK64)
    k3 = (((KL << 15 | KL >> 113) & MASK128) >> 64) & MASK64
    k4 = (((KL << 15 | KL >> 113) & MASK128) & MASK64)
    k5 = (((KA << 15 | KA >> 113) & MASK128) >> 64) & MASK64
    k6 = (((KA << 15 | KA >> 113) & MASK128) & MASK64)
    ke1 = (((KA << 30 | KA >> 98) & MASK128) >> 64) & MASK64
    ke2 = (((KA << 30 | KA >> 98) & MASK128) & MASK64)
    k7 = (((KL << 45 | KL >> 83) & MASK128) >> 64) & MASK64
    k8 = (((KL << 45 | KL >> 83) & MASK128) & MASK64)
    k9 = (((KA << 45 | KA >> 83) & MASK128) >> 64) & MASK64
    k10 = (((KL << 60 | KL >> 68) & MASK128) & MASK64)
    k11 = (((KA << 60 | KA >> 68) & MASK128) >> 64) & MASK64
    k12 = (((KA << 60 | KA >> 68) & MASK128) & MASK64)
    ke3 = (((KL << 77 | KL >> 51) & MASK128) >> 64) & MASK64
    ke4 = (((KL << 77 | KL >> 51) & MASK128) & MASK64)
    k13 = (((KL << 94 | KL >> 34) & MASK128) >> 64) & MASK64
    k14 = (((KL << 94 | KL >> 34) & MASK128) & MASK64)
    k15 = (((KA << 94 | KA >> 34) & MASK128) >> 64) & MASK64
    k16 = (((KA << 94 | KA >> 34) & MASK128) & MASK64)
    k17 = (((KL << 111 | KL >> 17) & MASK128) >> 64) & MASK64
    k18 = (((KL << 111 | KL >> 17) & MASK128) & MASK64)
    kw3 = (((KA << 111 | KA >> 17) & MASK128) >> 64) & MASK64
    kw4 = (((KA << 111 | KA >> 17) & MASK128) & MASK64)

def generate_192_256bit_subkeys(KL, KA, KR, KB):
    '''
    Function used to generate the subkeys for the 192 and 256-bit keys
    :param KL: The left part of the key
    :param KA: The KA part of the key
    :param KR: The right part of the key
    :return: None
    '''
    global kw1, kw2, kw3, kw4, k1, k2, k3, k4, k5, k6, ke1, ke2, k7, k8, k9, k10, k11, k12, ke3, ke4, k13, k14, k15, k16, k17, k18, ke5, ke6, k19, k20, k21, k22, k23, k24
    kw1 = (((KL << 0 | KL >> 128) & MASK128) >> 64) & MASK64
    kw2 = (((KL << 0 | KL >> 128) & MASK128) & MASK64)
    k1 = (((KB << 0 | KB >> 128) & MASK128) >> 64) & MASK64
    k2 = (((KB << 0 | KB >> 128) & MASK128) & MASK64)

    k3 = (((KR << 15 | KR >> 113) & MASK128) >> 64) & MASK64
    k4 = (((KR << 15 | KR >> 113) & MASK128) & MASK64)
    k5 = (((KA << 15 | KA >> 113) & MASK128) >> 64) & MASK64
    k6 = (((KA << 15 | KA >> 113) & MASK128) & MASK64)

    ke1 = (((KR << 30 | KR >> 98) & MASK128) >> 64) & MASK64
    ke2 = (((KR << 30 | KR >> 98) & MASK128) & MASK64)
    k7 = (((KB << 30 | KB >> 98) & MASK128) >> 64) & MASK64
    k8 = (((KB << 30 | KB >> 98) & MASK128) & MASK64)

    k9 = (((KL << 45 | KL >> 83) & MASK128) >> 64) & MASK64
    k10 = (((KL << 45 | KL >> 83) & MASK128) & MASK64)
    k11 = (((KA << 45 | KA >> 83) & MASK128) >> 64) & MASK64
    k12 = (((KA << 45 | KA >> 83) & MASK128) & MASK64)

    ke3 = (((KL << 60 | KL >> 68) & MASK128) >> 64) & MASK64
    ke4 = (((KL << 60 | KL >> 68) & MASK128) & MASK64)
    k13 = (((KR << 60 | KR >> 68) & MASK128) >> 64) & MASK64
    k14 = (((KR << 60 | KR >> 68) & MASK128) & MASK64)
    k15 = (((KB << 60 | KB >> 68) & MASK128) >> 64) & MASK64
    k16 = (((KB << 60 | KB >> 68) & MASK128) & MASK64)

    k17 = (((KL << 77 | KL >> 51) & MASK128) >> 64) & MASK64
    k18 = (((KL << 77 | KL >> 51) & MASK128) & MASK64)
    ke5 = (((KA << 77 | KA >> 51) & MASK128) >> 64) & MASK64
    ke6 = (((KA << 77 | KA >> 51) & MASK128) & MASK64)

    k19 = (((KR << 94 | KR >> 34) & MASK128) >> 64) & MASK64
    k20 = (((KR << 94 | KR >> 34) & MASK128) & MASK64)
    k21 = (((KA << 94 | KA >> 34) & MASK128) >> 64) & MASK64
    k22 = (((KA << 94 | KA >> 34) & MASK128) & MASK64)

    k23 = (((KL << 111 | KL >> 17) & MASK128) >> 64) & MASK64
    k24 = (((KL << 111 | KL >> 17) & MASK128) & MASK64)
    kw3 = (((KB << 111 | KB >> 17) & MASK128) >> 64) & MASK64
    kw4 = (((KB << 111 | KB >> 17) & MASK128) & MASK64)



def generate_ka_kb(KL, KR):
    '''
    Used to generate the KA and KB parts of the key
    :param KL: The left part of the key
    :param KR: The right part of the key
    :return: The KA and KB parts of the key
    '''
    # KB is not used for 128-bit keys
    D1 = (KL ^ KR) >> 64
    D2 = (KL ^ KR) & MASK64
    D2 = D2 ^ F(D1, Sigma1)
    D1 = D1 ^ F(D2, Sigma2)
    D1 = D1 ^ (KL >> 64)
    D2 = D2 ^ (KL & MASK64)
    D2 = D2 ^ F(D1, Sigma3)
    D1 = D1 ^ F(D2, Sigma4)
    KA = ((D1 << 64) | D2) & MASK128
    D1 = (KA ^ KR) >> 64
    D2 = (KA ^ KR) & MASK64
    D2 = D2 ^ F(D1, Sigma5)
    D1 = D1 ^ F(D2, Sigma6)
    KB = ((D1 << 64) | D2) & MASK128

    return KA, KB


def encrypt_128bits(M):
    '''
    Function used to encrypt the given 128-bit plaintext
    :param M: The plaintext to be encrypted
    :return: The encrypted cyphertext
    '''
    global kw1, kw2, kw3, kw4, k1, k2, k3, k4, k5, k6, ke1, ke2, k7, k8, k9, k10, k11, k12, ke3, ke4, k13, k14, k15, k16, k17, k18

    D1 = M >> 64
    D2 = M & MASK64

    D1 = D1 ^ kw1
    D2 = D2 ^ kw2
    D2 = D2 ^ F(D1, k1)
    D1 = D1 ^ F(D2, k2)
    D2 = D2 ^ F(D1, k3)
    D1 = D1 ^ F(D2, k4)
    D2 = D2 ^ F(D1, k5)
    D1 = D1 ^ F(D2, k6)
    D1 = FL(D1, ke1)
    D2 = FLINV(D2, ke2)
    D2 = D2 ^ F(D1, k7)
    D1 = D1 ^ F(D2, k8)
    D2 = D2 ^ F(D1, k9)
    D1 = D1 ^ F(D2, k10)
    D2 = D2 ^ F(D1, k11)
    D1 = D1 ^ F(D2, k12)
    D1 = FL(D1, ke3)
    D2 = FLINV(D2, ke4)
    D2 = D2 ^ F(D1, k13)
    D1 = D1 ^ F(D2, k14)
    D2 = D2 ^ F(D1, k15)
    D1 = D1 ^ F(D2, k16)
    D2 = D2 ^ F(D1, k17)
    D1 = D1 ^ F(D2, k18)
    D2 = D2 ^ kw3
    D1 = D1 ^ kw4

    C = (D2 << 64) | D1
    return C

def encrypt_192_256bits(M):
    '''
    Function used to encrypt the given 192 or 256-bit plaintext
    :param M: The plaintext to be encrypted
    :return: The encrypted cyphertext
    '''
    global kw1, kw2, kw3, kw4, k1, k2, k3, k4, k5, k6, ke1, ke2, k7, k8, k9, k10, k11, k12, ke3, ke4, k13, k14, k15, k16, k17, k18, ke5, ke6, k19, k20, k21, k22, k23, k24
    D1 = M >> 64
    D2 = M & MASK64

    D1 = D1 ^ kw1
    D2 = D2 ^ kw2
    D2 = D2 ^ F(D1, k1)
    D1 = D1 ^ F(D2, k2)
    D2 = D2 ^ F(D1, k3)
    D1 = D1 ^ F(D2, k4)
    D2 = D2 ^ F(D1, k5)
    D1 = D1 ^ F(D2, k6)
    D1 = FL(D1, ke1)
    D2 = FLINV(D2, ke2)
    D2 = D2 ^ F(D1, k7)
    D1 = D1 ^ F(D2, k8)
    D2 = D2 ^ F(D1, k9)
    D1 = D1 ^ F(D2, k10)
    D2 = D2 ^ F(D1, k11)
    D1 = D1 ^ F(D2, k12)
    D1 = FL(D1, ke3)
    D2 = FLINV(D2, ke4)
    D2 = D2 ^ F(D1, k13)
    D1 = D1 ^ F(D2, k14)
    D2 = D2 ^ F(D1, k15)
    D1 = D1 ^ F(D2, k16)
    D2 = D2 ^ F(D1, k17)
    D1 = D1 ^ F(D2, k18)
    D1 = FL(D1, ke5)
    D2 = FLINV(D2, ke6)
    D2 = D2 ^ F(D1, k19)
    D1 = D1 ^ F(D2, k20)
    D2 = D2 ^ F(D1, k21)
    D1 = D1 ^ F(D2, k22)
    D2 = D2 ^ F(D1, k23)
    D1 = D1 ^ F(D2, k24)
    D2 = D2 ^ kw3
    D1 = D1 ^ kw4

    C = (D2 << 64) | D1
    return C

def encrypt_128(plaintext):
    '''
    Function used to encrypt the given plaintext using the given 128-bit key
    :param plaintext: The plaintext to be encrypted
    :return: The encrypted cyphertext
    '''
    return encrypt_128bits(plaintext)

def encrypt_192(plaintext):
    '''
    Function used to encrypt the given plaintext using the given 192-bit key
    :param plaintext: The plaintext to be encrypted
    :return: The encrypted cyphertext
    '''
    return encrypt_192_256bits(plaintext)

def encrypt_256(plaintext):
    '''
    Function used to encrypt the given plaintext using the given 256-bit key
    :param plaintext: The plaintext to be encrypted
    :return: The encrypted cyphertext
    '''
    return encrypt_192_256bits(plaintext)

def decrypt(ciphertext, type=128):
    '''
    Utility function used to decide on what algorithm to use to decrypt the ciphertext based on the number of bits in the given key.
    :param text: The ciphertext to be decrypted
    :param type: The number of bits that the given key has: 128, 192 or 256
    :return: The decrypted plaintext
    '''
    if type == 128:
        return encrypt_128bits(ciphertext)
    if type == 192 or type == 256:
        return encrypt_192_256bits(ciphertext)


def inverse_subkeys(type=128):
    '''
    Function used to inverse the subkeys. It is used in the decryption process
    :param type: The number of bits that the given key has: 128, 192 or 256
    :return: None
    '''
    global kw1, kw2, kw3, kw4, k1, k2, k3, k4, k5, k6, ke1, ke2, k7, k8, k9, k10, k11, k12, ke3, ke4, k13, k14, k15, k16, k17, k18, ke5, ke6, k19, k20, k21, k22, k23, k24
    if type == 128:
        kw1, kw3 = kw3, kw1
        kw2, kw4 = kw4, kw2
        k1, k18 = k18, k1
        k2, k17 = k17, k2
        k3, k16 = k16, k3
        k4, k15 = k15, k4
        k5, k14 = k14, k5
        k6, k13 = k13, k6
        k7, k12 = k12, k7
        k8, k11 = k11, k8
        k9, k10 = k10, k9
        ke1, ke4 = ke4, ke1
        ke2, ke3 = ke3, ke2
    else:
        kw1, kw3 = kw3, kw1
        kw2, kw4 = kw4, kw2
        k1, k24 = k24, k1
        k2, k23 = k23, k2
        k3, k22 = k22, k3
        k4, k21 = k21, k4
        k5, k20 = k20, k5
        k6, k19 = k19, k6
        k7, k18 = k18, k7
        k8, k17 = k17, k8
        k9, k16 = k16, k9
        k10, k15 = k15, k10
        k11, k14 = k14, k11
        k12, k13 = k13, k12
        ke1, ke6 = ke6, ke1
        ke2, ke5 = ke5, ke2
        ke3, ke4 = ke4, ke3


# FILES - SUPPORT FUNCTIONS
READ_SIZE = 16
def encrypt_file(path, key, type=128, key_type='number', out_name='encrypted'):
    '''
    Function used to encrypt a given file using the Mitsubishi's Camellia algorithm
    :param path: The path to the file to be encrypted
    :param key: The key to be used in the encryption
    :param type: The number of bits that the given key has: 128, 192 or 256
    :param out_name: The name of the output file
    :param READ_SIZE:  The size of the bytes to be read from the file
    :return: None
    '''
    start_time = time.time()
    total_bytes = 0
    print('Started the encryption...')

    if key_type == 'file':
        print("Reading the key...")
        with open(key, 'rb') as f:
            key = f.read(type)
            key = bytes.hex(key)
            key = int(key, 16)
        print("Key read successfully")
    print('Expanding the key...')
    KL, KR = prepare_key(key, type)
    KA, KB = generate_ka_kb(KL, KR)
    if type == 128:
        generate_128bit_subkeys(KL, KA)
    elif type == 192 or type == 256:
        generate_192_256bit_subkeys(KL, KA, KR, KB)
    print('Key expanded successfully')
    with open(path, 'rb') as f:
        print('Opened the input file...')
        with open(out_name, 'wb') as out:
            while True:
                # Read the bytes of the file
                text = f.read(READ_SIZE)
                total_bytes += len(text)
                # Check for EOF
                if not text:
                    break
                # Start encrypting the bytes as you read them
                text = bytes.hex(text)
                text = int(text, 16)
                if type == 128:
                    encoded = encrypt_128(text)
                elif type == 192:
                    encoded = encrypt_192(text)
                elif type == 256:
                    encoded = encrypt_256(text)
                out.write(encoded.to_bytes(READ_SIZE, byteorder='big'))
    end_time = time.time()
    print(f'Successfully encrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds')
    print(f'The encryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')

def decrypt_file(path, key, type=128, key_type='number', out_name='decrypted'):
    '''
    Function used to decrypt a given file using the Mitsubishi's Camellia algorithm
    :param path: The path to the file to be decrypted
    :param key: The key to be used in the decryption
    :param type: The number of bits that the given key has: 128, 192 or 256
    :param out_name: The name of the output file
    :return: None
    '''
    start_time = time.time()
    total_bytes = 0
    print('Started the decryption...')

    if key_type == 'file':
        print("Reading the key...")
        with open(key, 'rb') as f:
            key = f.read(type)
            key = bytes.hex(key)
            key = int(key, 16)
        print("Key read successfully")

    print('Expanding the key...')
    KL, KR = prepare_key(key, type)
    KA, KB = generate_ka_kb(KL, KR)
    if type == 128:
        generate_128bit_subkeys(KL, KA)
    elif type == 192 or type == 256:
        generate_192_256bit_subkeys(KL, KA, KR, KB)
    print('Key expanded successfully')

    print('Inversing the subkeys...')
    inverse_subkeys(type)
    print('Inverted the subkeys successfully')

    with open(path, 'rb') as f:
        with open(out_name, 'wb') as out:
            while True:
                # Read the bytes of the file
                text = f.read(READ_SIZE)
                total_bytes += len(text)
                # Check for EOF
                if not text:
                    break
                # Start decrypting the bytes as you read them
                text = bytes.hex(text)
                text = int(text, 16)
                encoded = decrypt(text, type)
                # Write the decrypted bytes to the output file
                out.write(encoded.to_bytes(16, byteorder='big'))
    end_time = time.time()
    print(f'Successfully decrypted the file and wrote {total_bytes} bytes in {end_time - start_time} seconds')
    print(f'The decryption speed is {total_bytes / (end_time - start_time)} bytes per second \n')


# key_128 = 0x0123456789abcdeffedcba9876543210
# plaintext = 0x0123456789abcdeffedcba9876543210
# encoded = encrypt_128(plaintext, key_128)
# print(hex(encoded))
# print(hex(decrypt(key_128, encoded, 128)))
#
#
# key_192 = 0x0123456789abcdeffedcba98765432100011223344556677
# encoded = encrypt_192(plaintext, key_192)
# print('\n', hex(encoded))
# print(hex(decrypt(key_192, encoded, 192)))
#
# key_256 = 0x0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff
# encoded = encrypt_256(plaintext, key_256)
# print('\n', hex(encoded))
# print(hex(decrypt(key_256, encoded, 256)))


# 67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43
# key_192 = 0x0123456789abcdeffedcba98765432100011223344556677
# encoded = encrypt_192(plaintext, key_192)
# print(hex(encoded))
# b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9
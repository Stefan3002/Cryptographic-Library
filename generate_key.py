import random
import secrets
import gmpy2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
# key = 0x0123456789abcdeffedcba9876543210
# key_size = 256

def generate_camellia_key(num_bits=128, out_name='key'):
    key = secrets.token_bytes(num_bits//8)
    with open(out_name, 'wb') as out:
        out.write(key)

def generate_chacha_key(out_name='key'):
    '''
    Function to generate a chacha key, store  it in a file and return a nonce
    :param out_name: name of the file to store the key
    :return: nonce
    '''
    key = secrets.token_hex(256//8)
    with open(out_name, 'w') as out:
        out.write(key)
    return secrets.token_hex(10)

def generate_rsa_keypair(out_pub_name='rsa_pub_key', out_priv_name='rsa_private_key'):
    '''
    Function to generate a RSA key pair and store it in two files (public and private)
    :param out_pub_name: Name of the file to store the public key
    :param out_priv_name: Name of the file to store the private key
    :return: Tuple with the public and private keys
    '''
    # Get some random numbers
    n1 = random.randint(1, 10)
    n2 = random.randint(1, 10)
    # Get a big prime number
    p = gmpy2.next_prime(10 ** n1 + 200)
    # And another one
    q = gmpy2.next_prime(10 ** n2 + 123)
    # Multiply them to get n
    n = gmpy2.mul(p, q)
    phi = (p - 1) * (q - 1)
    # e must a be a number coprime with phi
    e = gmpy2.next_prime(max(p, q) + 1)
    d = gmpy2.invert(e, phi)

    # CRYPTOGRAPHIC LIBRARY WAS USED ONLY TO WRITE THE KEYS IN PEM FORMAT, THEY ARE MANUALLY GENERATED ABOVE
    # Create a public key object
    public_numbers = rsa.RSAPublicNumbers(int(e), int(n))
    public_key = public_numbers.public_key(default_backend())

    # Serialize public key to PEM format
    pem_format = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Write the PEM-formatted public key to a file
    with open(f"{out_pub_name}.pem", "wb") as f:
        f.write(pem_format)

    # Create a private key object
    private_numbers = rsa.RSAPrivateNumbers(
        p=int(p),  # Prime factor p
        q=int(q),  # Prime factor q
        d=int(d),
        dmp1=int(gmpy2.mod(d, p - 1)),  # d mod (p-1)
        dmq1=int(gmpy2.mod(d, q - 1)),  # d mod (q-1)
        iqmp=int(gmpy2.powmod(q, -1,  p)),  # q^-1 mod p
        public_numbers=public_numbers
    )

    private_key = private_numbers.private_key(default_backend())

    # Serialize private key to PEM format
    pem_format = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write the PEM-formatted private key to a file
    with open(f"{out_priv_name}.pem", "wb") as f:
        f.write(pem_format)


    return ((e, n), (d, n))

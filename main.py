import camellia
import generate_key
import chacha
import rsa

# CAMELLIA
key_size = 128
generate_key.generate_camellia_key(key_size, 'key-camellia')
camellia.encrypt_file('AI1_Plan.pdf', 'key-camellia', key_size, 'file', 'camellia-encrypted')
camellia.decrypt_file('camellia-encrypted', 'key-camellia', key_size, 'file', 'camellia-decrypted')

#
#  CHACHA20
# nonce = generate_key.generate_chacha_key('key-chacha')
# chacha.encrypt_file('AI1_Plan.pdf', 'key-chacha', nonce, 'file', 'chacha20-encrypted')
# chacha.decrypt_file('chacha20-encrypted', 'key-chacha', nonce, 'file', 'chacha20-decrypted')
#


# RSA

# # Get a key pair
# # generate_key.generate_rsa_keypair()
# message = "Hello, RSA!"
# # Read the key
# public_key = rsa.read_public_key("rsa_pub_key.pem")
# encrypted_message = rsa.encrypt(public_key, 'AI1_Plan.pdf', 'file', 'rsa_encrypted')
#
# # Read the other key
# private_key = rsa.read_private_key("rsa_private_key.pem")
# decrypted_message = rsa.decrypt(private_key, 'rsa_encrypted', 'file', 'rsa_decrypted')

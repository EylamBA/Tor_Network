import rsa
import base64

# function to create the rsa keys
def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(512)  
    return get_raw_key(public_key), get_raw_key(private_key)

# function to get just the base64-encoded key
def get_raw_key(key):
    key_pem = key.save_pkcs1()
    return base64.b64encode(key_pem).decode('utf-8')

# function to convert base64-encoded key to RSA key object
def load_key_from_raw(raw_key, key_type='public'):
    key_bytes = base64.b64decode(raw_key)
    if key_type == 'public':
        return rsa.PublicKey.load_pkcs1(key_bytes)
    elif key_type == 'private':
        return rsa.PrivateKey.load_pkcs1(key_bytes)

# function to encrypt the aes key
def encrypt_message(message_bytes, public_key_raw):
    public_key = load_key_from_raw(public_key_raw, key_type='public')
    encrypted_message = rsa.encrypt(message_bytes, public_key)
    return encrypted_message

# function to decrypt the aes key
def decrypt_message(encrypted_message, private_key_raw):
    private_key = load_key_from_raw(private_key_raw, key_type='private')
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message

# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: light
#       format_version: '1.5'
#       jupytext_version: 1.15.2
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# # Naivistisk pseudo og re-pseudo

# +
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_keys():
    """
    Generate a pair of public and private keys.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key):
    """
    Serialize a key (private or public) for storage.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def save_keys(keys, base_dir="key_storage"):
    """
    Save the serialized keys to files with references.
    """
    os.makedirs(base_dir, exist_ok=True)
    references = {}
    for i, (private_key, public_key) in enumerate(keys, 1):
        ref = f"keypair_{i}"
        references[ref] = {
            'public': f"{base_dir}/{ref}_public.pem",
            'private': f"{base_dir}/{ref}_private.pem"
        }
        with open(references[ref]['public'], 'wb') as f:
            f.write(serialize_key(public_key))
        with open(references[ref]['private'], 'wb') as f:
            f.write(serialize_key(private_key))
    return references

def load_key(file_path):
    """
    Load a key from a file.
    """
    with open(file_path, 'rb') as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None, backend=default_backend()) if "private" in file_path else serialization.load_pem_public_key(key_data, backend=default_backend())

def re_pseudonymize(encrypted, from_ref, to_ref, key_references):
    """
    Decrypt using one key and re-encrypt using another.
    """
    private_key = load_key(key_references[from_ref]['private'])
    public_key = load_key(key_references[to_ref]['public'])
    
    # Decrypt
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Re-encrypt
    re_encrypted = public_key.encrypt(
        original_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return re_encrypted


# -

# Generate and store 10 keys
keys = [generate_keys() for _ in range(10)]
key_references = save_keys(keys)

# Example usage
message = "Sensitive Data"
encrypted_message = encrypt_data(serialize_key(keys[0][1]), message)
re_encrypted_message = re_pseudonymize(encrypted_message, 'keypair_1', 'keypair_6', key_references)
print("Re-encrypted:", re_encrypted_message)



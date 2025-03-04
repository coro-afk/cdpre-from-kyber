# Description: This file demonstrates the use of the Kyber library and the cdPRE library in security of AES128.
# The Kyber library is used to generate a public key, secret key, ciphertext, and message.
# The cdPRE library is used to generate a re-encryption key and re-encrypt a ciphertext.
# The libraries are loaded using CFFI and the shared libraries are loaded from the avx2 folder.

from KDF_chain import kdf, generate_kdfc_key, generate_aes128_key
from KDF_tree import generate_tree, generate_kdft_keys
import os
import hashlib
import cffi
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random
import math
from tabulate import tabulate

# Create a CFFI object
ffi = cffi.FFI()

# Define the C code of the Kyber library and cdPRE
ffi.cdef("""
typedef int16_t poly[256];

typedef struct {
    poly vec[4]; // Assuming KYBER_K is 4, adjust if necessary
} polyvec;

void pqcrystals_kyber512_avx2_indcpa_keypair_derand(uint8_t pk[800], uint8_t sk[1632], const uint8_t coins[32]);

void pqcrystals_kyber512_avx2_indcpa_enc(uint8_t c[768], const uint8_t m[32], const uint8_t pk[800], const uint8_t coins[32]);

void pqcrystals_kyber512_avx2_indcpa_dec(uint8_t m[32], const uint8_t c[768], const uint8_t sk[1632]);
""")
ffi.cdef("""
void cdpre_rkg(uint8_t sk_i[1632],
               const uint8_t pk_j[800],
               const uint8_t c_i[768],
               uint8_t rk[768],
               const uint8_t coins[32]);

void cdpre_renc(const uint8_t rk[768],
                const uint8_t c_i[768],
                uint8_t c_j[768]);
""")

# Load the shared library
libindcpa_path = os.path.join(os.path.dirname(__file__), '../avx2/libindcpa.so')
libcdpre_path = os.path.join(os.path.dirname(__file__), '../avx2/libcdpre.so')
libindcpa = ffi.dlopen(libindcpa_path)
libcdpre = ffi.dlopen(libcdpre_path)

def encrypt_data(sek, data):
    """Encrypt the data using the provided sek."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(sek), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cm = encryptor.update(padded_data) + encryptor.finalize()
    return cm, iv

def decrypt_data(sek, iv, cm):
    """Decrypt the data using the provided sek and iv."""
    cipher = Cipher(algorithms.AES(sek), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(cm) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    dm = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return dm

# KDF chain
def test_kdf_chain(n, e, pka, ska, pkb, skb):
    m = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
    ck = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    rk = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    dk = generate_aes128_key()
    results = []
    for i in range(e):
        sek, dk = generate_kdfc_key(i, dk)
    
    for i in range(e, n):
        row = [f'Epoch {i}']
        m = f'Simulated data for epoch {i}'.encode()
        dkp = dk
        sek, dk = generate_kdfc_key(i, dk)
        
        row.append(bytes(m).decode())
        
        # Encrypt the data
        cm, iv = encrypt_data(sek, m)
        row.append(cm[:16].hex())

        if i == e:
            # Only need re-encryption in the first epoch
            # Encrypt the dk
            coinse = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
            libindcpa.pqcrystals_kyber512_avx2_indcpa_enc(ck, dkp, pka, coinse)
            hck = hashlib.sha256(bytes(ck)).digest()[:16]
            
            # Compute the re-encryption key
            coinsab = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
            libcdpre.cdpre_rkg(ska, pkb, ck, rk, coinsab)
            hrk = hashlib.sha256(bytes(rk)).digest()[:16]
            print(f'Truncated re-encryption key: {bytes(rk)[:16].hex()}')
            
            # Re-encrypt the key ciphertext
            ckp = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
            libcdpre.cdpre_renc(rk, ck, ckp)
            hckp = hashlib.sha256(bytes(ckp)).digest()[:16]
            
            # Decrypt the re-encrypted key ciphertext
            dkpp = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
            libindcpa.pqcrystals_kyber512_avx2_indcpa_dec(dkpp, ckp, skb)
            dkpp = bytes(dkpp)[:16]
            
            # Retrieve the sek
            sekp, dkk = generate_kdfc_key(i, dkpp)
            
            # Decrypt the data ciphertext
            dm = decrypt_data(sekp, iv, cm)
            row.append(dm.decode())
        else:
            # Data buyer compute the sek
            sekp, dkk = generate_kdfc_key(i, dkk)
            
            # Decrypt the data ciphertext
            dm = decrypt_data(sekp, iv, cm)
            row.append(dm.decode())
        
        results.append(row)
    
    headers = ["Epoch", "(DO) Data", "(PS) Truncated data ciphertext", "(DB) Decrypted data"]
    print(tabulate(results, headers=headers, tablefmt="grid"))
    print()

# KDF tree
def test_kdf_tree(n, e, pka, ska, pkb, skb):
    l = math.ceil(math.log2(n))
    dk, sek = generate_tree(n)
    sekp = {}
    m = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
    ck = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    ckp = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    rk = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    results = []
    
    sek_hex = {k: v.hex() for k, v in sek.items()}
    
    epoch_keys = generate_kdft_keys(e, dk, sek, n)
    
    for i in e:
        row = [f'Epoch {i}']
        m = f'Simulated data for epoch {i}'.encode()
        
        row.append(bytes(m).decode())
        
        # Encrypt the data
        cm, iv = encrypt_data(sek[f'{i:0{l}b}'], m)
        row.append(cm[:16].hex())

        if i == e[0]:
            # Only need re-encryption in the first epoch
            # Proxy server
            # Encrypt the dk
            edk = {}
            for k, v in epoch_keys.items():
                coinse = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
                libindcpa.pqcrystals_kyber512_avx2_indcpa_enc(ck, v, pka, coinse)
                edk[k] = bytes(ck)
            
            # Re-encrypt the dk ciphertext
            rks = {}
            ckps = {}
            print("\nTruncated re-encryption keys:")
            for k, v in edk.items():
                coinsab = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
                libcdpre.cdpre_rkg(ska, pkb, v, rk, coinsab)
                rks[k] = rk
                # Re-encrypt the key ciphertext
                libcdpre.cdpre_renc(rk, v, ckp)
                ckps[k] = bytes(ckp)
                print(f"{k}: {v[:16].hex()}")
            
            # Data buyer
            epoch_keysp = {}
            stack = []
            for k, v in ckps.items():
                # Decrypt the re-encrypted key ciphertext
                dkpp = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
                libindcpa.pqcrystals_kyber512_avx2_indcpa_dec(dkpp, v, skb)
                epoch_keysp[k] = bytes(dkpp)[:16]
                stack.append((k, len(k)))
            # Retrieve the sek
            while stack:
                parent_key, depth = stack.pop()
                if depth == l:
                    sekp[parent_key] = epoch_keysp[parent_key]
                    continue
                else:
                    direction = 0 if parent_key == '' or parent_key[-1] == '0' else 1
                    epoch_keysp[parent_key + '0'], epoch_keysp[parent_key + '1'] = kdf(epoch_keysp[parent_key], direction)
                    stack.append((parent_key + '1', depth + 1))
                    stack.append((parent_key + '0', depth + 1))
                    
        # Decrypt the data ciphertext
        dm = decrypt_data(sekp[f'{i:0{l}b}'], iv, cm)
        row.append(dm.decode())
        
        results.append(row)
    
    headers = ["Epoch", "(DO) Data", "(PS) Truncated Data ciphertext", "(DB) Decrypted data"]
    print(tabulate(results, headers=headers, tablefmt="grid"))

# Define constants
KYBER_INDCPA_PUBLICKEYBYTES = 800
KYBER_INDCPA_SECRETKEYBYTES = 1632
KYBER_INDCPA_BYTES = 768
KYBER_INDCPA_MSGBYTES = 32
KYBER_SYMBYTES = 32

if __name__ == '__main__':
    # Key pairs for data owner and buyer
    pka = ffi.new("uint8_t[]", KYBER_INDCPA_PUBLICKEYBYTES)
    ska = ffi.new("uint8_t[]", KYBER_INDCPA_SECRETKEYBYTES)
    coinsa = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
    pkb = ffi.new("uint8_t[]", KYBER_INDCPA_PUBLICKEYBYTES)
    skb = ffi.new("uint8_t[]", KYBER_INDCPA_SECRETKEYBYTES)
    coinsb = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
    
    # Generate key pairs
    libindcpa.pqcrystals_kyber512_avx2_indcpa_keypair_derand(pka, ska, coinsa)
    libindcpa.pqcrystals_kyber512_avx2_indcpa_keypair_derand(pkb, skb, coinsb)

    # Print the hash of pks
    hpka = hashlib.sha256(bytes(pka)).digest()
    print(f"Alice's Public Key (hashed): {hpka.hex()}")
    hpkb = hashlib.sha256(bytes(pkb)).digest()
    print(f"Bob's Public Key (hashed): {hpkb.hex()}")
    print()
    
    n = 8
    # Test the KDF chain
    print(f'KDF Chain of {n} epochs.')
    e = random.randint(0, n - 1)
    print(f'Data buyer starts subscription at epoch {e}.\n')
    test_kdf_chain(n, e, pka, ska, pkb, skb)
    
    # Test the KDF tree
    print(f'KDF Tree of {n} epochs.')
    e = random.sample(range(n), random.randint(1, n))
    e.sort()
    print(f'Data buyer subscripts epochs {e}.')
    test_kdf_tree(n, e, pka, ska, pkb, skb)



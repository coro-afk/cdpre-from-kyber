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

# KDF chain
def test_kdf_chain(n, e, pka, ska, pkb, skb):
    m = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
    ck = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    rk = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    dk = generate_aes128_key()
    for i in range(e):
        sek, dk = generate_kdfc_key(i, dk)
    
    for i in range(e, n):
        print(f'--------Epoch {i}--------')
        m = f'Simulated data for epoch {i}'.encode()
        dkp = dk
        sek, dk = generate_kdfc_key(i, dk)
        
        print('(Data owner) Encryption key sek:', sek.hex())
        print('(Data owner) Derivative key dk:', dkp.hex())
        print('(Data owner) Data:', bytes(m).decode())
        
        # Encrypt the data
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(sek), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(m) + padder.finalize()
        
        cm = encryptor.update(padded_data) + encryptor.finalize()
        print("(Proxy server) Data ciphertext (Truncated):", cm[:16].hex())

        
        if i == e:
            # Only need re-encryption in the first epoch
            # Encrypt the dk
            coinse = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
            libindcpa.pqcrystals_kyber512_avx2_indcpa_enc(ck, dkp, pka, coinse)
            hck = hashlib.sha256(bytes(ck)).digest()[:16]
            print("(Proxy server) Key ciphertext (hashed):", hck.hex())
            
            # Compute the re-encryption key
            coinsab = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
            libcdpre.cdpre_rkg(ska, pkb, ck, rk, coinsab)
            hrk = hashlib.sha256(bytes(rk)).digest()[:16]
            print("(Proxy server) Re-encryption Key (hashed):", hrk.hex())
            
            # Re-encrypt the key ciphertext
            ckp = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
            libcdpre.cdpre_renc(rk, ck, ckp)
            hckp = hashlib.sha256(bytes(ckp)).digest()[:16]
            print("(Proxy server) Re-encrypted Ciphertext (hashed):", hckp.hex())
            
            # Decrypt the re-encrypted key ciphertext
            dkpp = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
            libindcpa.pqcrystals_kyber512_avx2_indcpa_dec(dkpp, ckp, skb)
            dkpp = bytes(dkpp)[:16]
            print("(Data buyer) Decrypted Re-encrypted key:", dkpp.hex())
            
            # Retrieve the sek
            sekp, dkk = generate_kdfc_key(i, dkpp)
            print('(Data buyer) Decrypted sek:', sekp.hex())
            
            # Decrypt the data ciphertext
            cipher = Cipher(algorithms.AES(sekp), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded_data = decryptor.update(cm) + decryptor.finalize()
            
            # Unpad the decrypted data
            unpadder = padding.PKCS7(128).unpadder()
            dm = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            print("(Data buyer) Decrypted data:", dm.decode())

            print()
        else:
            # Data buyer compute the sek
            sekp, dkk = generate_kdfc_key(i, dkk)
            
            # Decrypt the data ciphertext
            cipher = Cipher(algorithms.AES(sekp), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded_data = decryptor.update(cm) + decryptor.finalize()
            
            # Unpad the decrypted data
            unpadder = padding.PKCS7(128).unpadder()
            dm = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            print("(Data buyer) Decrypted data:", dm.decode())

            print()
        
# KDF tree
def test_kdf_tree(n, e, pka, ska, pkb, skb):
    l = math.ceil(math.log2(n))
    dk, sek = generate_tree(n)
    m = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
    ck = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    rk = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
    
    sek_hex = {k: v.hex() for k, v in sek.items()}
    print("\nSEK (Leaf Keys):")
    for k, v in sek_hex.items():
        print(f"{k}: {v}")
    
    epoch_keys = generate_kdft_keys(e, dk, sek, n)
    print("\nEpoch Keys:")
    print(epoch_keys)
    
    for i in e:
        print(f'--------Epoch {i}--------')
        m = f'Simulated data for epoch {i}'.encode()
        
        print('(Data owner) Encryption key sek:', sek[f'{i:0{l}b}'].hex())
        print('(Data owner) Data:', bytes(m).decode())
        
        # Encrypt the data
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(sek[f'{i:0{l}b}']), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(m) + padder.finalize()
        
        cm = encryptor.update(padded_data) + encryptor.finalize()
        print("(Proxy server) Data ciphertext (Truncated):", cm[:16].hex())

        if i == e[0]:
            # Only need re-encryption in the first epoch
            # Encrypt the dk
            edk = {}
            for k, v in epoch_keys.items():
                coinse = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
                libindcpa.pqcrystals_kyber512_avx2_indcpa_enc(ck, v, pka, coinse)
                edk[k] = ck
            # Re-encrypt the key ciphertext
            rks = {}
            epoch_keysp = {}
            stack = []
            for k, v in edk.items():
                coinsab = ffi.new("uint8_t[]", os.urandom(KYBER_SYMBYTES))
                libcdpre.cdpre_rkg(ska, pkb, v, rk, coinsab)
                rks[k] = rk
                
                # Re-encrypt the key ciphertext
                ckp = ffi.new("uint8_t[]", KYBER_INDCPA_BYTES)
                libcdpre.cdpre_renc(rk, v, ckp)
                
                # Decrypt the re-encrypted key ciphertext
                dkpp = ffi.new("uint8_t[]", KYBER_INDCPA_MSGBYTES)
                libindcpa.pqcrystals_kyber512_avx2_indcpa_dec(dkpp, ckp, skb)
                epoch_keysp[k] = bytes(dkpp)[:16]
                stack.append((k, len(k)))
            print(stack)
            print(epoch_keysp)
            # Retrieve the sek
            sekp = {}
            while stack:
                parent_key, depth = stack.pop()
                if depth == l:
                    sekp[parent_key] = epoch_keysp[parent_key]
                    continue
                for i in range(depth, l):
                    epoch_keysp[parent_key + '0'], epoch_keysp[parent_key + '1'] = kdf(epoch_keysp[parent_key], k[-1])
                    stack.append((parent_key + '0', i + 1))
                    stack.append((parent_key + '1', i + 1))
            
    
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
    print("Alice's Public Key (hashed):", hpka.hex())
    hpkb = hashlib.sha256(bytes(pkb)).digest()
    print("Bob's Public Key (hashed):", hpkb.hex())
    print()
    
    # Test the KDF chain
    n = 8
    print(f'KDF Chain of {n} epochs.')
    e = random.randint(0, n - 1)
    print(f'Data buyer starts subscription at epoch {e}.\n')
    test_kdf_chain(n, e, pka, ska, pkb, skb)
    
    # Test the KDF tree
    n = 8
    print(f'KDF Tree of {n} epochs.')
    e = [1, 2]
    print(f'Data buyer starts subscription at epoch {e}.\n')
    test_kdf_tree(n, e, pka, ska, pkb, skb)



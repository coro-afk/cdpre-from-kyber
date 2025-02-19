/* Deterministic randombytes by Daniel J. Bernstein */
/* taken from SUPERCOP (https://bench.cr.yp.to)     */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../indcpa.h"
#include "../randombytes.h"
#include "../fips202.h"
#include "../cdpre.h"

#define NTESTS 1

int main(void)
{
  unsigned int i, j;
  uint8_t coins32[KYBER_SYMBYTES];
  uint8_t pk_i[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_i[CRYPTO_SECRETKEYBYTES];
  uint8_t pk_j[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_j[CRYPTO_SECRETKEYBYTES];
  uint8_t ct_i[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rk[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ct_j[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_i[CRYPTO_BYTES];
  uint8_t key_j[CRYPTO_BYTES];

  for (i = 0; i < NTESTS; i++) {
    randombytes(coins32, KYBER_SYMBYTES);

    // Key-pair generation for i
    indcpa_keypair_derand(pk_i, sk_i, coins32);
    printf("i's Public Key: ");
    for (j = 0; j < CRYPTO_PUBLICKEYBYTES; j++)
      printf("%02x", pk_i[j]);
    printf("\n");
    printf("i's Secret Key: ");
    for (j = 0; j < CRYPTO_SECRETKEYBYTES; j++)
      printf("%02x", sk_i[j]);
    printf("\n");

    randombytes(coins32, KYBER_SYMBYTES);

    // Key-pair generation for j
    indcpa_keypair_derand(pk_j, sk_j, coins32);
    printf("j's Public Key: ");
    for (j = 0; j < CRYPTO_PUBLICKEYBYTES; j++)
      printf("%02x", pk_j[j]);
    printf("\n");
    printf("j's Secret Key: ");
    for (j = 0; j < CRYPTO_SECRETKEYBYTES; j++)
      printf("%02x", sk_j[j]);
    printf("\n");

    randombytes(coins32, KYBER_SYMBYTES);

    // Generate random key_i
    randombytes(key_i, CRYPTO_BYTES);

    // Encryption
    indcpa_enc(ct_i, key_i, pk_i, coins32);
    printf("Ciphertext ct_i: ");
    for (j = 0; j < CRYPTO_CIPHERTEXTBYTES; j++)
      printf("%02x", ct_i[j]);
    printf("\n");
    printf("Shared Secret key_i: ");
    for (j = 0; j < CRYPTO_BYTES; j++)
      printf("%02x", key_i[j]);
    printf("\n");

    randombytes(coins32, KYBER_SYMBYTES);

    // Re-key generation by i
    cdpre_rkg(sk_i, pk_j, ct_i, rk, coins32);
    printf("Re-key rk: ");
    for (j = 0; j < CRYPTO_CIPHERTEXTBYTES; j++)
      printf("%02x", rk[j]);
    printf("\n");

    // Re-encryption by j/proxy
    cdpre_renc(rk, ct_i, ct_j);
    printf("Ciphertext ct_j: ");
    for (j = 0; j < CRYPTO_CIPHERTEXTBYTES; j++)
      printf("%02x", ct_j[j]);
    printf("\n");

    // Decryption by j
    indcpa_dec(key_j, ct_j, sk_j);
    printf("Shared Secret key_j: ");
    for (j = 0; j < CRYPTO_BYTES; j++)
      printf("%02x", key_j[j]);
    printf("\n");
  }
  return 0;
}

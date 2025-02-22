/* Deterministic randombytes by Daniel J. Bernstein */
/* taken from SUPERCOP (https://bench.cr.yp.to)     */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../indcpa.h"
#include "../randombytes.h"
#include "../fips202.h"
#include "../satopre.h"

#define NTESTS 1

int main(void)
{
  unsigned int i, j;
  uint8_t coins1[KYBER_SYMBYTES];
  uint8_t coins2[KYBER_SYMBYTES];
  uint8_t pk1_i[KYBER_PUBLICKEYBYTES];
  uint8_t sk1_i[KYBER_SECRETKEYBYTES];
  uint8_t pk2_i[KYBER_PUBLICKEYBYTES];
  uint8_t sk2_i[KYBER_SECRETKEYBYTES];

  for (i = 0; i < NTESTS; i++) {
	// Key-pair generation for i
    randombytes(coins1, KYBER_SYMBYTES);
	randombytes(coins2, KYBER_SYMBYTES);
    satopre_keypair(pk1_i, sk1_i, pk2_i, sk2_i, coins1, coins2);
    printf("i's first Public Key: ");
    for (j = 0; j < KYBER_PUBLICKEYBYTES; j++)
      printf("%02x", pk1_i[j]);
    printf("\n");
    printf("i's first Secret Key: ");
    for (j = 0; j < KYBER_SECRETKEYBYTES; j++)
      printf("%02x", sk1_i[j]);
    printf("\n");

	
	printf("i's second Public Key: ");
    for (j = 0; j < KYBER_PUBLICKEYBYTES; j++)
      printf("%02x", pk2_i[j]);
    printf("\n");
    printf("i's second Secret Key: ");
    for (j = 0; j < KYBER_SECRETKEYBYTES; j++)
      printf("%02x", sk2_i[j]);
    printf("\n");
  }
  return 0;
}

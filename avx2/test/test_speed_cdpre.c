#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../params.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#include "../cdpre.h"

#define NTESTS 1

uint64_t t[NTESTS];

int main(void)
{
	unsigned int i;
	uint8_t coins32[KYBER_SYMBYTES];
	uint8_t sk_i[KYBER_SECRETKEYBYTES];
	uint8_t pk_j[KYBER_PUBLICKEYBYTES];
	uint8_t ct_i[KYBER_CIPHERTEXTBYTES];
	uint8_t rk[KYBER_CIPHERTEXTBYTES];
	uint8_t ct_j[KYBER_CIPHERTEXTBYTES];

  randombytes(coins32, KYBER_SYMBYTES);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    cdpre_rkg(sk_i, pk_j, ct_i, rk, coins32);
  }
  print_results("cdpre_rkg: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    cdpre_renc(rk, ct_i, ct_j);
  }
  print_results("cdpre_renc: ", t, NTESTS);

  return 0;
}

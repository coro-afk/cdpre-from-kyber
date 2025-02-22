#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../kem.h"
#include "../params.h"
#include "../indcpa.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 10000

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

int main(void)
{
  const unsigned int l = 12; // l = \lceil\log_2(q)\rightceil

  unsigned int i, j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t coins32[KYBER_SYMBYTES];
  uint8_t coins64[2*KYBER_SYMBYTES];
  polyvec matrix[KYBER_K];
  poly ap;

  randombytes(coins32, KYBER_SYMBYTES);
  randombytes(coins64, 2*KYBER_SYMBYTES);

  // satopre_keypair
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_keypair_derand(pk, sk, coins32);
	indcpa_keypair_derand(pk, sk, coins32);
  }
  print_results("satopre_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_enc(ct, key, pk, seed);
  }
  print_results("satopre_enc: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_dec(key, ct, sk);
  }
  print_results("satopre_dec: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
	t[i] = cpucycles();
	poly_decompress(&ap,ct); // decompress pk
	// generate noise: R1 \gets \beta^{k\times k\ell}_{\eta_1}
	for(j = 0; j < (KYBER_K * KYBER_K * l); j++) { 
		poly_getnoise_eta2(&ap, seed, 0);
	}
	// generate noise: R2, r3 \gets \beta^{k\ell}_{\eta_2}\times \beta^{k}_{\eta_2}
	for(j = 0; j < (KYBER_K * KYBER_K * l + KYBER_K); j++) { 
		poly_getnoise_eta2(&ap, seed, 0);
  	}
	// compute A^T * R1
	for(j = 0; j < (KYBER_K * KYBER_K * l); j++) {
		poly_ntt(&ap);
	}
	for(j = 0; j < (KYBER_K * KYBER_K * l); j++) {
		polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
	}
	for(j = 0; j < (KYBER_K * KYBER_K * l); j++){
		poly_invntt_tomont(&ap);
	}
	// compute A^T * R1 + R3
	for(j = 0; j < (KYBER_K * KYBER_K * l); j++){
		poly_add(&ap, &ap, &ap);
	}
	// compute \hat{t}_B^T * R1
	for(j = 0; j < (KYBER_K * l); j++) {
		poly_ntt(&ap);
	}
	for(j = 0; j < (KYBER_K * l); j++){
		polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
	}
	for(j = 0; j < (KYBER_K * l); j++) {
		poly_invntt_tomont(&ap);
	}
	// compute \hat{t}_B^T * R1 + r3 - s_A^T
	for(j = 0; j < (KYBER_K * l); j++){
		poly_add(&ap, &ap, &ap);
	}
	for(j = 0; j < (KYBER_K * l); j++){
		poly_sub(&ap, &ap, &ap);
	}
  }
  print_results("satopre_rkg: ", t, NTESTS);

  for(i=0; i<NTESTS; i++){
	t[i] = cpucycles();
	// decompress ciphertext
	polyvec_decompress(&matrix[0],ct);
	poly_decompress(&ap,ct);
	// compute uB
	for(j = 0; j < (KYBER_K); j++) {
		poly_ntt(&ap);
	}
	for(j = 0; j < (KYBER_K * l); j++){
		polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
	}
	for(j = 0; j < (KYBER_K); j++) {
		poly_invntt_tomont(&ap);
	}
	// compute vB
	for(j = 0; j < (KYBER_K); j++) {
		poly_ntt(&ap);
	}
	for(j = 0; j < (KYBER_K); j++){
		polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
	}
	for(j = 0; j < (KYBER_K); j++) {
		poly_invntt_tomont(&ap);
	}
	poly_add(&ap, &ap, &ap);
	// compress ciphertext
	polyvec_compress(ct,&matrix[0]);
	poly_compress(ct,&ap);
  }
  print_results("satopre_renc: ", t, NTESTS);



  return 0;
}
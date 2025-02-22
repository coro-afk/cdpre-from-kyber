#ifndef SATOPRE_H
#define SATOPRE_H

#include <stdint.h>

void satopre_keypair(uint8_t pk1[KYBER_INDCPA_PUBLICKEYBYTES],
	uint8_t sk1[KYBER_INDCPA_SECRETKEYBYTES],
	uint8_t pk2[KYBER_INDCPA_PUBLICKEYBYTES],
	uint8_t sk2[KYBER_INDCPA_SECRETKEYBYTES],
	const uint8_t coins1[KYBER_SYMBYTES],
	const uint8_t coins2[KYBER_SYMBYTES]);

#endif // SATOPRE_H
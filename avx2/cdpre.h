#ifndef CDPRE_H
#define CDPRE_H

#include "indcpa.h" // 包含 indcpa.h 以避免重复声明

void cdpre_rkg(uint8_t sk_i[KYBER_INDCPA_SECRETKEYBYTES],
               const uint8_t pk_j[KYBER_INDCPA_PUBLICKEYBYTES],
               const uint8_t c_i[KYBER_INDCPA_BYTES],
               uint8_t rk[KYBER_INDCPA_BYTES],
               const uint8_t coins[KYBER_SYMBYTES]);

void cdpre_renc(const uint8_t rk[KYBER_INDCPA_BYTES],
                const uint8_t c_i[KYBER_INDCPA_BYTES],
                uint8_t c_j[KYBER_INDCPA_BYTES]);

#endif // CDPRE_H
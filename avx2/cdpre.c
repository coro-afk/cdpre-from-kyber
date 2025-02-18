#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "rejsample.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        cdpre_rkg
*
* Description: Re-encryption generation
*
* Arguments:   - const uint8_t *sk_i: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
*              - const uint8_t *pk_j: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *c_i: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
*              - const uint8_t *c_j: pointer to output ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
**************************************************/
void cdpre_rkg(uint8_t sk_i[KYBER_INDCPA_SECRETKEYBYTES],
  const uint8_t pk_j[KYBER_INDCPA_PUBLICKEYBYTES],
  const uint8_t c_i[KYBER_INDCPA_BYTES],
  const uint8_t coins[KYBER_SYMBYTES],
  uint8_t c_j[KYBER_INDCPA_BYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  polyvec sp, pkpv, skpv, ep, at[KYBER_K], b_i, b_j;
  poly v_i, v_j, epp, mp; // useless error term epp

  unpack_pk(&pkpv, seed, pk_j);
  unpack_sk(&skpv, sk_i);
  unpack_ciphertext(&b_i, &v_i, c_i);
  gen_at(at, seed);

#if KYBER_K == 2
  poly_getnoise_eta1122_4x(sp.vec+0, sp.vec+1, ep.vec+0, ep.vec+1, coins, 0, 1, 2, 3);
  poly_getnoise_eta2(&epp, coins, 4);
#elif KYBER_K == 3
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, ep.vec+0, coins, 0, 1, 2 ,3);
  poly_getnoise_eta1_4x(ep.vec+1, ep.vec+2, &epp, b_j.vec+0, coins,  4, 5, 6, 7);
#elif KYBER_K == 4
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, sp.vec+3, coins, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(ep.vec+0, ep.vec+1, ep.vec+2, ep.vec+3, coins, 4, 5, 6, 7);
  poly_getnoise_eta2(&epp, coins, 8);
#endif

  polyvec_ntt(&sp);

  // computing u
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b_j.vec[i], &at[i], &sp);
  polyvec_invntt_tomont(&b_j);
  polyvec_add(&b_j, &b_j, &ep);
  polyvec_reduce(&b_j);

  // computing v
  polyvec_basemul_acc_montgomery(&v_j, &pkpv, &sp);// t_j^T * r
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b_i); // s_i^T * u_i
  poly_invntt_tomont(&mp);
  poly_sub(&v_j, &v_j, &mp);
  poly_reduce(&v_j);

  pack_ciphertext(c_j, &b_j, &v_j);
}

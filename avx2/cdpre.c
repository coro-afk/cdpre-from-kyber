#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "indcpa.h"
#include "cdpre.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "rejsample.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key.
*              The polynomial coefficients in sk are assumed to
*              lie in the invertal [0,q], i.e. sk must be reduced
*              by polyvec_reduce().
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
// static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
// {
//   polyvec_tobytes(r, sk);
// }

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v.
*              The polynomial coefficients in b and v are assumed to
*              lie in the invertal [0,q], i.e. b and v must be reduced
*              by polyvec_reduce() and poly_reduce(), respectively.
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output array
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
// static unsigned int rej_uniform(int16_t *r,
//                                 unsigned int len,
//                                 const uint8_t *buf,
//                                 unsigned int buflen)
// {
//   unsigned int ctr, pos;
//   uint16_t val0, val1;

//   ctr = pos = 0;
//   while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
//     val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
//     val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
//     pos += 3;

//     if(val0 < KYBER_Q)
//       r[ctr++] = val0;
//     if(ctr < len && val1 < KYBER_Q)
//       r[ctr++] = val1;
//   }

//   return ctr;
// }

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

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
  uint8_t rk[KYBER_INDCPA_BYTES],
  const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec pkpv, skpv, rp, ep, at[KYBER_K], u_ij, u_i;
  poly v_i, v_ij, temp;
  // unpacking
  unpack_pk(&pkpv, seed, pk_j); // parse pk_j
  unpack_sk(&skpv, sk_i); // parse sk_j
  unpack_ciphertext(&u_i, &v_i, c_i); //parse c_i
  gen_at(at, seed); // generate matrix A^T

  // generate u_ij
  for(i=0;i<KYBER_K;i++) // generate rp
  	poly_getnoise_eta1(rp.vec+i, coins, nonce++);
  polyvec_ntt(&rp);
  for(i=0;i<KYBER_K;i++) // A^T * rp
	polyvec_basemul_acc_montgomery(&u_ij.vec[i], &at[i], &rp);
  for(i=0;i<KYBER_K;i++) // generate ep
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  polyvec_invntt_tomont(&u_ij);
  polyvec_add(&u_ij, &u_ij, &ep); // u_ij = A^T * rp + ep
  
  polyvec_reduce(&u_ij); // compress u_ij

  // generate v_ij
  polyvec_basemul_acc_montgomery(&v_ij, &pkpv, &rp); // t_j^T * rp
  poly_invntt_tomont(&v_ij);
  polyvec_ntt(&u_i);
  polyvec_basemul_acc_montgomery(&temp, &skpv, &u_i); // s_i^T * u_i
  poly_invntt_tomont(&temp);

  poly_sub(&v_ij, &v_ij, &temp); // v_ij = t_j^T * rp - s_i^T * u_i
  poly_reduce(&v_ij); // compress v_ij
  /* optimistic mode: drv = 4 */
  /* need to add other modes, i.e., different compression size for v_ij */

  // pack ciphertext
  pack_ciphertext(rk, &u_ij, &v_ij);

}

/*************************************************
* Name:        cdpre_renc
*
* Description: Re-encryption generation
*
* Arguments:   - const uint8_t *rk: pointer to input re-key
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *c_i: pointer to input ciphertext
*                             ./     (of length KYBER_INDCPA_BYTES)
*              - uint8_t *c_j: pointer to output ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
**************************************************/

void cdpre_renc(const uint8_t rk[KYBER_INDCPA_BYTES],
  const uint8_t c_i[KYBER_INDCPA_BYTES],
  uint8_t c_j[KYBER_INDCPA_BYTES])
{
	polyvec u_i, u_j;
	poly v_ij, v_i, v_j;

	unpack_ciphertext(&u_j, &v_ij, rk); // parse rk, and u_j = u_ij
	/* need to be optimized: do not need to unpack/pack u_j */
	unpack_ciphertext(&u_i, &v_i, c_i); // parse c_i
	
	poly_add(&v_j, &v_i, &v_ij); // v_j = v_i + v_ij
	poly_reduce(&v_j); // compress v_j
	polyvec_reduce(&u_j); // compress u_j

	pack_ciphertext(c_j, &u_j, &v_j); // pack c_j
}
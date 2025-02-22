#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "indcpa.h"
#include "satopre.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "rejsample.h"
#include "symmetric.h"
#include "randombytes.h"
#include "fips202.h"
#include "fips202x4.h"

static const l = 12;

static void concatenate_pks(uint8_t combined_pk[2 * KYBER_INDCPA_PUBLICKEYBYTES],
    const uint8_t pk1[KYBER_INDCPA_PUBLICKEYBYTES],
    const uint8_t pk2[KYBER_INDCPA_PUBLICKEYBYTES])
{
    memcpy(combined_pk, pk1, KYBER_INDCPA_PUBLICKEYBYTES);
    memcpy(combined_pk + KYBER_INDCPA_PUBLICKEYBYTES, pk2, KYBER_INDCPA_PUBLICKEYBYTES);
}

static void split_pks(uint8_t pk1[KYBER_INDCPA_PUBLICKEYBYTES],
    uint8_t pk2[KYBER_INDCPA_PUBLICKEYBYTES],
    const uint8_t combined_pk[2 * KYBER_INDCPA_PUBLICKEYBYTES])
{
    memcpy(pk1, combined_pk, KYBER_INDCPA_PUBLICKEYBYTES);
    memcpy(pk2, combined_pk + KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_PUBLICKEYBYTES);
}

static void concatenate_sks(uint8_t combined_sk[2 * KYBER_INDCPA_SECRETKEYBYTES],
    const uint8_t sk1[KYBER_INDCPA_SECRETKEYBYTES],
    const uint8_t sk2[KYBER_INDCPA_SECRETKEYBYTES])
{
    memcpy(combined_sk, sk1, KYBER_INDCPA_SECRETKEYBYTES);
    memcpy(combined_sk + KYBER_INDCPA_SECRETKEYBYTES, sk2, KYBER_INDCPA_SECRETKEYBYTES);
}

static void split_sks(uint8_t sk1[KYBER_INDCPA_SECRETKEYBYTES],
    uint8_t sk2[KYBER_INDCPA_SECRETKEYBYTES],
    const uint8_t combined_sk[2 * KYBER_INDCPA_SECRETKEYBYTES])
{
    memcpy(sk1, combined_sk, KYBER_INDCPA_SECRETEYBYTES);
    memcpy(sk2, combined_sk + KYBER_INDCPA_SECRETEYBYTES, KYBER_INDCPA_SECRETEYBYTES);
}

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
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
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
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
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
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        generate_noise_matrix
*
* Description: Generate a noise matrix with the specified noise generation function
*
* Arguments:   - polyvec R[KYBER_K][l]: output noise matrix
*              - const uint8_t noiseseed[KYBER_SYMBYTES]: input noise seed
*              - void (*noise_func_4x)(poly *r0, poly *r1, poly *r2, poly *r3, const uint8_t *seed, uint8_t nonce0, uint8_t nonce1, uint8_t nonce2, uint8_t nonce3): noise generation function
*              - void (*noise_func)(poly *r, const uint8_t *seed, uint8_t nonce)
**************************************************/
static void generate_noise_matrix(polyvec R[KYBER_K][l], const uint8_t noiseseed[KYBER_SYMBYTES],
                                  void (*noise_func_4x)(poly *r0, poly *r1, poly *r2, poly *r3, const uint8_t *seed, uint8_t nonce0, uint8_t nonce1, uint8_t nonce2, uint8_t nonce3),
                                  void (*noise_func)(poly *r, const uint8_t *seed, uint8_t nonce))
{
    unsigned int j, k;
    uint8_t nonce = 0;

    if (KYBER_K == 2) {
        for (j = 0; j < l; j += 1) {
            noise_func_4x(R[0][j].vec + 0, R[0][j].vec + 1, R[1][j].vec + 0, R[1][j].vec + 1, noiseseed, nonce++, nonce++, nonce++, nonce++);
        }
    } else if (KYBER_K == 3) {
        for (j = 0; j < l; j += 1) {
            noise_func_4x(R[0][j].vec + 0, R[0][j].vec + 1, R[0][j].vec + 2, R[1][j].vec + 0, noiseseed, nonce++, nonce++, nonce++, nonce++);
            noise_func_4x(R[1][j].vec + 1, R[1][j].vec + 2, R[2][j].vec + 0, R[2][j].vec + 1, noiseseed, nonce++, nonce++, nonce++, nonce++);
            noise_func(R[2][j].vec + 2, noiseseed, nonce++);
        }
    } else if (KYBER_K == 4) {
        for (j = 0; j < KYBER_K * l; j += 1) {
            for (k = 0; k < KYBER_K; k++) {
                noise_func_4x(R[k][j].vec + 0, R[k][j].vec + 1, R[k][j].vec + 2, R[k][j].vec + 3, noiseseed, nonce++, nonce++, nonce++, nonce++);
            }
        }
    }
}

// generate noise matrix R1 using poly_getnoise_eta1_4x and poly_getnoise_eta1
static void generate_R1_matrix(polyvec R[KYBER_K][l], const uint8_t noiseseed[KYBER_SYMBYTES])
{
    generate_noise_matrix(R, noiseseed, poly_getnoise_eta1_4x, poly_getnoise_eta1);
}

// generate noise matrix R2 using poly_getnoise_eta2_4x and poly_getnoise_eta2
static void generate_R2_matrix(polyvec R[KYBER_K][l], const uint8_t noiseseed[KYBER_SYMBYTES])
{
    generate_noise_matrix(R, noiseseed, poly_getnoise_eta2_4x, poly_getnoise_eta2);
}

// get keypairs
void satopre_keypair(uint8_t pk[2 * KYBER_INDCPA_PUBLICKEYBYTES],
                     uint8_t sk[2 * KYBER_INDCPA_SECRETKEYBYTES],
                     const uint8_t coins1[KYBER_SYMBYTES],
                     const uint8_t coins2[KYBER_SYMBYTES])
{
    uint8_t pk1[KYBER_INDCPA_PUBLICKEYBYTES], sk1[KYBER_INDCPA_SECRETKEYBYTES], pk2[KYBER_INDCPA_PUBLICKEYBYTES], sk2[KYBER_INDCPA_SECRETKEYBYTES];
    indcpa_keypair_derand(pk1, sk1, coins1);
    indcpa_keypair_derand(pk2, sk2, coins2);

    concatenate_pks(pk, pk1, pk2);
    concatenate_sks(sk, sk1, sk2);
}

// re-key generation
void satopre_rkg(uint8_t sk_i[2 * KYBER_INDCPA_SECRETKEYBYTES],
                 const uint8_t pk_j[2 * KYBER_INDCPA_PUBLICKEYBYTES],
                 const uint8_t coins[KYBER_SYMBYTES])
{
    uint8_t pk1_j[KYBER_INDCPA_PUBLICKEYBYTES], pk2_j[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk1_i[KYBER_INDCPA_SECRETKEYBYTES], sk2_i[KYBER_INDCPA_SECRETKEYBYTES];
    uint8_t rk1[KYBER_INDCPA_BYTES], rk2[KYBER_INDCPA_BYTES];
    uint8_t seed[KYBER_SYMBYTES];
    polyvec pkpv, at[KYBER_K];
    polyvec R1[KYBER_K][l], R2[KYBER_K][l], U[KYBER_K][l], r3;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    unsigned int i, j;

    gen_at(at, seed); // A^T

    split_pks(pk1_j, pk2_j, pk_j);
    split_sks(sk1_i, sk2_i, sk_i);

    unpack_pk(&pkpv, seed, pk2_j); // \hat{t}_j \gets Decompression

    generate_R1_matrix(&R1, noiseseed); // R1 \gets \beta_\eta^{k\times k\ell}
    generate_R2_matrix(&R2, noiseseed); // R2 \gets \beta_\eta^{k\times k\ell}
    generate_polyvec(&r3, noiseseed); // r3 \gets \beta_\eta^k

	// compute A^T * R1
	for (j = 0; j < l; j++) {
		for (i = 0; i < KYBER_K; i++) {
			polyvec_basemul_acc_montgomery(&U[i][j], &at[i], &R1[i][j]);
		}
	}

	// compute U = A^T * R1 + R2
	for (j = 0; j < l; j++) {
		for (i = 0; i < KYBER_K; i++) {
			polyvec_add(&U[i][j], &U[i][j], &R2[i][j]);
		}
	}

	// compute \hat{t}_B^T * R1
	for (j = 0; j < l; j++) {
		polyvec_basemul_acc_montgomery(&r3, &pkpv, &R1[i][j]);
	}
}
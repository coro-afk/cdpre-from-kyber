# Ciphertext-dependent proxy re-encryption scheme from Kyber

This repository is a fork from [Kyber](https://www.pq-crystals.org/kyber/).

This repository contains the implementation of a cipheretext-dependent Proxy Re-Encryption scheme based on Kyber.

The Kyber description:
> This repository contains the official reference implementation of the [Kyber](https://www.pq-crystals.org/kyber/) key encapsulation mechanism, 
> and an optimized implementation for x86 CPUs supporting the AVX2 instruction set. 
> Kyber has been selected for standardization in [round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) 
> of the [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) standardization project.


## Build instructions

The implementations contain several test and benchmarking programs and a Makefile to facilitate compilation.

### Prerequisites

Some of the test programs require [OpenSSL](https://openssl.org). 
If the OpenSSL header files and/or shared libraries do not lie in one of the standard locations on your system, 
it is necessary to specify their location via compiler and linker flags in the environment variables `CFLAGS`, `NISTFLAGS`, and `LDFLAGS`.

For example, on macOS you can install OpenSSL via [Homebrew](https://brew.sh) by running
```sh
brew install openssl
```
Then, run
```sh
export CFLAGS="-I/usr/local/opt/openssl@1.1/include"
export NISTFLAGS="-I/usr/local/opt/openssl@1.1/include"
export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
```
before compilation to add the OpenSSL header and library locations to the respective search paths.

### Building all binaries

To compile the test and benchmarking programs on Linux or macOS, go to the `ref/` or `avx2/` directory and run
```sh
make
```
This produces the executables
```sh
test/test_kyber$ALG
test/test_vectors$ALG
test/test_speed$ALG

test/test_vectors_cdpre$ALG
test/test_speed_cdpre$ALG
test/test_speed_satopre$ALG
```
where `$ALG` ranges over the parameter sets 512, 768, 1024.

* `test_kyber$ALG` tests 1000 times to generate keys, encapsulate a random key and correctly decapsulate it again. 
  Also, the program tests that the keys cannot correctly be decapsulated using a random secret key 
  or a ciphertext where a single random byte was randomly distorted in order to test for trivial failures of the CCA security. 
  The program will abort with an error message and return 1 if there was an error. 
  Otherwise it will output the key and ciphertext sizes and return 0.
* `test_vectors$ALG` generates 10000 sets of test vectors containing keys, ciphertexts and shared secrets 
  whose byte-strings are output in hexadecimal. It also generates test vector for decapsulation of invalid
  (pseudorandom) ciphertexts.
  The required random bytes are deterministic and come from SHAKE128 on empty input.
* `test_speed$ALG` reports the median and average cycle counts of 1000 executions of various internal functions 
  and the API functions for key generation, encapsulation and decapsulation. 
  By default the Time Step Counter is used. 
  If instead you want to obtain the actual cycle counts from the Performance Measurement Counters, export `CFLAGS="-DUSE_RDPMC"` before compilation.

* `test_vectors_cdpre$ALG` (New) generates 1000 sets of cdPRE test vectors containing keys, ciphertexts, re-encryption key generation, re-ecnryption ciphertexts, and shared secrets whose byte-strings are output in hexadecimal.
* `test_speed_cdpre$ALG` (New) reports the median and average cycle counts of 1000 executions of internal functions and the API functions for cdPRE re-encryption key generation and proxy re-encryption. By default the Time Step Counter is used. 
* `test_speed_sato$ALG` (New) reports the median and average cycle counts of 1000 executions of simulated functions for satoPRE key-pair generation, encryption, decryption, re-encryption key generation, and proxy re-encryption. By default the Time Step Counter is used. 


Please note that the reference implementation in `ref/` is not optimized for any platform, and, since it prioritises clean code, 
is significantly slower than a trivially optimized but still platform-independent implementation. 
Hence benchmarking the reference code does not provide particularly meaningful results.

## Shared libraries

All implementations can be compiled into shared libraries by running
```sh
make shared
```
For the demo system, the required libraries are
```
libcdpre.so
libindcpa.so
```

## Demo system for a data subscription protocol

The demo system illustrates the usage of epoch symmetric key generation (KDF chain and KDF tree) and cdPRE in a data subscription scenario.

* `demo/demo.py`: For simplicity, the outputs omit the intermediate calculation process and variables. First, Alice (delegator) uploads the encrypted data (simulated data for some epoch) and encrypted key on a proxy server (PS); when Bob (delegatee) requests the data access, Alice computes a re-encryption key and sends it to PS; PS re-encrypts the key ciphertext; finally, DB accesses the key ciphertext and decrypts it by its private key to get the data encryption key, and decrypt the data ciphertext to obtain the data (simulated data for some epoch).


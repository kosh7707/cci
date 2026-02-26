/* CCI AES-128 / SHA-256 */
#define CCI_KEY_BYTES 16
#define CCI_KEY_BITS  128
#define CCI_CTR_EVP   EVP_aes_128_ctr
#define CCI_HASH_FN   EVP_sha256
#include "crypto_aead.h"
#include "cci_core.inc"

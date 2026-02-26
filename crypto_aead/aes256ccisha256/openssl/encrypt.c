/* CCI AES-256 / SHA-256 */
#define CCI_KEY_BYTES 32
#define CCI_KEY_BITS  256
#define CCI_CTR_EVP   EVP_aes_256_ctr
#define CCI_HASH_FN   EVP_sha256
#include "crypto_aead.h"
#include "cci_core.inc"

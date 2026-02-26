/* CCI AES-128 / BLAKE3 */
#define CCI_KEY_BYTES  16
#define CCI_KEY_BITS   128
#define CCI_CTR_EVP    EVP_aes_128_ctr
#define CCI_USE_BLAKE3 1
#include "blake3.h"
#include "crypto_aead.h"
#include "cci_core.inc"

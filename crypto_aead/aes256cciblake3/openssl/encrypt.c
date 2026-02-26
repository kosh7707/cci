/* CCI AES-256 / BLAKE3 */
#define CCI_KEY_BYTES  32
#define CCI_KEY_BITS   256
#define CCI_CTR_EVP    EVP_aes_256_ctr
#define CCI_USE_BLAKE3 1
#include "blake3.h"
#include "crypto_aead.h"
#include "cci_core.inc"

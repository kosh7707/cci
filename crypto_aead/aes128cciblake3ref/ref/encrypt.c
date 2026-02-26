/* CCI-128-BLAKE3 pure software reference implementation */
#define CCI_KEY_BYTES 16
#include "aes_portable.inc"
#define CCI_USE_BLAKE3 1
#include "blake3.h"
#include "crypto_aead.h"
#include "cci_core_ref.inc"

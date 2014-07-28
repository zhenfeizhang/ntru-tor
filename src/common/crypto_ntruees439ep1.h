#ifndef TOR_CRYPTO_NTRUEES439EP1_H
#define TOR_CRYPTO_NTRUEES439EP1_H

/** Length of a ntruees439ep1 public key when encoded. */
#define NTRUEES439EP1_PUBKEY_LEN 609
/** Length of a ntruees439ep1 secret key when encoded. */
#define NTRUEES439EP1_SECKEY_LEN 659
/** Length of a single ntruees439ep1 ciphertext. */
#define NTRUEES439EP1_CIPHERTEXT_LEN 604
/** Maximum plaintext length in ntruees439ep1 ciphertext. */
#define NTRUEES439EP1_MAX_PT_LEN 65

typedef struct ntruees439ep1_public_key_t {
  uint8_t public_key[NTRUEES439EP1_PUBKEY_LEN];
} ntruees439ep1_public_key_t;

typedef struct ntruees439ep1_secret_key_t {
  uint8_t secret_key[NTRUEES439EP1_SECKEY_LEN];
} ntruees439ep1_secret_key_t;

typedef struct ntruees439ep1_ciphertext_t {
  uint8_t ciphertext[NTRUEES439EP1_CIPHERTEXT_LEN];
} ntruees439ep1_ciphertext_t;

typedef struct ntruees439ep1_keypair_t {
  ntruees439ep1_public_key_t pubkey;
  ntruees439ep1_secret_key_t seckey;
} ntruees439ep1_keypair_t;


int ntruees439ep1_keypair_generate(ntruees439ep1_public_key_t *pk,
                                   ntruees439ep1_secret_key_t *sk);

int ntruees439ep1_encrypt(const ntruees439ep1_public_key_t *pk,
                           const size_t msg_len,
                           const uint8_t *msg,
                           ntruees439ep1_ciphertext_t *ct);

int ntruees439ep1_decrypt(const ntruees439ep1_secret_key_t *sk,
                          const ntruees439ep1_ciphertext_t *ct,
                          uint16_t pt_len,
                          uint8_t *pt);

#endif

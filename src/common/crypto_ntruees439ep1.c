/* Wrapper around an NTRUEES439EP1 implementation */

#define CRYPTO_NTRUEES439EP1_PRIVATE
#include "orconfig.h"
#include "crypto.h"
#include "crypto_ntruees439ep1.h"
#include <libntruencrypt/ntru_crypto.h>
#include <libntruencrypt/ntru_crypto_drbg.h>

int
randombytes(char *out, size_t num_bytes)
{
  if (crypto_rand(out, num_bytes) < 0)
  {
    DRBG_RET(DRBG_ENTROPY_FAIL);
  }
  DRBG_RET(DRBG_OK);
}

int
ntruees439ep1_keypair_generate(ntruees439ep1_public_key_t *pk,
                               ntruees439ep1_secret_key_t *sk)
{
  DRBG_HANDLE drbg;
  uint16_t    pk_len;
  uint16_t    sk_len;
  uint32_t    rc;

  rc = ntru_crypto_external_drbg_instantiate((RANDOM_BYTES_FN)&randombytes, &drbg);
  if (rc != DRBG_OK)
  {
    return 1;
  }

  /* Check that our implementation really supports ees439ep1 */
  rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES439EP1, &pk_len,
                                       NULL, &sk_len, NULL);
  if (rc != NTRU_OK)
  {
    ntru_crypto_drbg_uninstantiate(drbg);
    return 1;
  }

  if(pk_len != NTRUEES439EP1_PUBKEY_LEN || sk_len != NTRUEES439EP1_SECKEY_LEN)
  {
    ntru_crypto_drbg_uninstantiate(drbg);
    return 1;
  }

  /* Generate a key */
  do
  {
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES439EP1,
                                         &pk_len, pk->public_key,
                                         &sk_len, sk->secret_key);
    /* NTRU_FAIL signals that we should try again */
  } while(rc == NTRU_RESULT(NTRU_FAIL));
  /* For other errors we should abort */
  if (rc != NTRU_OK)
  {
    ntru_crypto_drbg_uninstantiate(drbg);
    return 1;
  }

  ntru_crypto_drbg_uninstantiate(drbg);
  return 0;
}

int
ntruees439ep1_encrypt(const ntruees439ep1_public_key_t *pk,
                      const size_t msg_len,
                      const uint8_t *msg,
                      ntruees439ep1_ciphertext_t *ct)
{
  DRBG_HANDLE drbg;
  uint16_t    ct_len;
  uint32_t    rc;

  rc = ntru_crypto_external_drbg_instantiate((RANDOM_BYTES_FN)&randombytes, &drbg);
  if (rc != DRBG_OK)
  {
    return 1;
  }

  /* Ensure this encrypt routine outputs NTRUEES439EP1_CIPHERTEXT_LEN bytes */
  rc = ntru_crypto_ntru_encrypt(drbg, NTRUEES439EP1_PUBKEY_LEN, pk->public_key,
                                0, NULL, &ct_len, NULL);
  if(rc != NTRU_OK || ct_len != NTRUEES439EP1_CIPHERTEXT_LEN)
  {
    ntru_crypto_drbg_uninstantiate(drbg);
    return 1;
  }

  rc = ntru_crypto_ntru_encrypt(drbg, NTRUEES439EP1_PUBKEY_LEN, pk->public_key,
                                msg_len, msg, &ct_len, ct->ciphertext);
  if(rc != NTRU_OK)
  {
    ntru_crypto_drbg_uninstantiate(drbg);
    return 1;
  }

  ntru_crypto_drbg_uninstantiate(drbg);
  return 0;
}

int
ntruees439ep1_decrypt(const ntruees439ep1_secret_key_t *sk,
                      const ntruees439ep1_ciphertext_t *ct,
                      uint16_t expected_pt_len,
                      uint8_t *pt)
{
  /* We only need to decrypt plaintexts of known size, so allocate
   * enough space to hold the maximum length, but ensure that the
   * actual plaintext matches the expected size */
  uint8_t     pt_buf[NTRUEES439EP1_MAX_PT_LEN];
  uint16_t    pt_len = NTRUEES439EP1_MAX_PT_LEN;
  uint32_t    rc;

  rc = ntru_crypto_ntru_decrypt(NTRUEES439EP1_SECKEY_LEN, sk->secret_key,
                                NTRUEES439EP1_CIPHERTEXT_LEN, ct->ciphertext,
                                &pt_len, pt_buf);
  if (rc != NTRU_OK || pt_len != expected_pt_len)
  {
    return 1;
  }

  memcpy(pt, pt_buf, expected_pt_len);

  return 0;
}

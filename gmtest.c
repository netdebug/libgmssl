#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

static FILE *openkeyfile(const char *path) {
  FILE *in;
  in = fopen(path, "r");
  if (!in) {
    perror("openkeyfile");
    return NULL;
  }
  return in;
}

static void ch2hex(char *dst, const unsigned char *src, int srclen)
{
  int i;
  for (i = 0; i < srclen; i++)
    sprintf(&(dst[i * 2]), "%02x", src[i]);
}

#include "sm3.h"
int testsm3(unsigned char *in, int ilen,
            unsigned char out[SM3_DIGEST_LENGTH])
{
  sm3(in, ilen, out);		/* sm3 returns void */
  return 1;
}


int testsm3evp(unsigned char *in, int ilen,
               unsigned char out[SM3_DIGEST_LENGTH])
{
  EVP_MD_CTX *md_ctx = NULL;
  md_ctx = EVP_MD_CTX_create();
  const EVP_MD *md = EVP_sm3(); //segment fault
  //const EVP_MD *md = EVP_sha256();
  if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
    printf("init err\n");
    return 0;
  }
  if (!EVP_DigestUpdate(md_ctx, in, ilen)) {
    printf("update err\n");
    return 0;
  }
  int olen = 32;
  if (!EVP_DigestFinal_ex(md_ctx, out, &olen))  {
    printf("final err\n");
    return 0;
  }

  return 1;

}

#include "sms4.h"

int main()
{
  int i, ret;
  unsigned char out[1024];
  char outhex[2048];
  const char *expect;


  printf("--- sm3 ---   ");
  expect = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

  testsm3("abc", strlen("abc"), out);

  ch2hex(outhex, out, SM3_DIGEST_LENGTH);
  if (memcmp(outhex, expect, SM3_DIGEST_LENGTH*2) != 0) {
    printf("FAILS\n");
    printf("ret: %s\n", outhex);
    printf("exp: %s\n", expect);
  } else {
    printf("OK\n");
  }

  printf("--- sm3 evp ---   ");      /* OK */
  memset(out, 0, SM3_DIGEST_LENGTH);
  testsm3evp("abc", strlen("abc"), out);
  ch2hex(outhex, out, SM3_DIGEST_LENGTH);
  if (memcmp(outhex, expect, SM3_DIGEST_LENGTH*2) != 0) {
    printf("FAILS\n");
    printf("ret: %s\n", outhex);
    printf("exp: %s\n", expect);
  } else {
    printf("OK\n");
  }


  printf("--- sm4 ecb enc ---   ");
  unsigned char key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
  expect = "681edf34d206965e86b3e94f536e4246";
  sms4_key_t k;
  sms4_set_encrypt_key(&k, key);
  sms4_encrypt(key, out, &k);         /* key as in */
  ch2hex(outhex, out, sizeof(key));
  if (memcmp(outhex, expect, sizeof(key)*2) != 0) {
    printf("FAILS\n");
    printf("ret: %s\n", outhex);
    printf("exp: %s\n", expect);
  } else {
    printf("OK\n");
  }

  printf("--- sm4 ecb dec ---   ");
  expect="0123456789abcdeffedcba9876543210";
  unsigned char dec[16];
  sms4_set_decrypt_key(&k, key);
  sms4_decrypt(out, dec, &k);
  // testsm4(key, SM4_ECB | SM4_DECRYPT, NULL, out, sizeof(key), dec);
  ch2hex(outhex, dec, sizeof(key));
  if (memcmp(outhex, expect, sizeof(key)*2) != 0) {
    printf("FAILS\n");
    printf("ret: %s\n", outhex);
    printf("exp: %s\n", expect);
  } else {
    printf("OK\n");
  }

  return 0;
}

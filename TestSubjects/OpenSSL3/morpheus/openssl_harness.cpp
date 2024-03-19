#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void printBuf( uint8_t *buf, size_t buf_len )
{
    for (size_t i = 0; i < buf_len; i++)
    {
        printf("%02hhx ", buf[i]);
        if ( (i+1) % 32 == 0)
            printf("\n");
        else if ( (i+1) % 16 == 0 )
            printf(" ");
    }
    printf("\n");
}

// datahex reads hex string and returns bytes array
uint8_t* datahex(char* string, size_t *dlength) {

    if(string == NULL) 
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0)
       return NULL;

    *dlength = slength / 2;

    uint8_t* data = (uint8_t *)malloc(*dlength);
    memset(data, 0, *dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F') 
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
          free(data);
          return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

int main(int argc, char *argv[])
{

    fclose(stderr);
    // stderr = fopen("/dev/null","w");

    if(argc != 2)
    {
        printf("usage: %s <signature-hex-string>\n", argv[0]);
    	return 0;
    }
    
    size_t siglen;
    uint8_t *sig = datahex(argv[1], &siglen);

    int ret;

    char pubkeyPEM[] = 
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIIBCAKCAQEA6TKskiUvWFs6gKTddqiXyLdlKVL+eI9uyN1kBYeh7lZHZwqK1MK+\n"
    "D5+m5JxgWt93tRdCMK971Q5dbW1tKMzwqIalFMxy5R0gnMdypS70GfapU/MTWSlY\n"
    "jr6bNR/KYc7XjzRv4A27YwblwqTG38N3mvhatBc3HPNNg4e5swrkbXpf9aZVuNhF\n"
    "XxuUrnNpidYKby/Vytv/vVBMWnVqLmu1zswTvKdQP234tSrOXEEJl+mICdtNww2U\n"
    "PeToEqR1U9zlSESnjjZAHRP3fcZQYZ/tiNizkm49jjGcgMdEd5rF1qviUolpUJF0\n"
    "duzl6Pwn1fBT1gGNkbUCxHh1WKACuSg9pwIBAw==\n"
    "-----END RSA PUBLIC KEY-----\n";

    EVP_MD_CTX *md_ctx_verify = EVP_MD_CTX_new();
    assert(md_ctx_verify != NULL);

    BIO *pkbio = BIO_new_mem_buf(pubkeyPEM, sizeof(pubkeyPEM));
    assert(pkbio != NULL);

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(pkbio, NULL, 0, NULL);
    assert(pkey != NULL);

    ret = EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(), NULL, pkey);
    assert(ret);

    char msg[] = "hello world!";
    ret = EVP_DigestVerifyUpdate(md_ctx_verify, msg, strlen(msg));
    assert(ret);

    ret = EVP_DigestVerifyFinal(md_ctx_verify, sig, siglen);

    if (ret) {
        printf("ret = 0\n");
    } else {
        printf("ret = -1\n");
    }

    return 0;
}


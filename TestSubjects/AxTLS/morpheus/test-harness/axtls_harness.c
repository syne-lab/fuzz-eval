#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../ssl/os_port.h"
#include "../ssl/crypto_misc.h"

// Cyiu: this is to mimic how sig_verify() is being called, based on
// int x509_verify() in ssl/x509.c
int x509_verify_mimic(uint8_t *digest, int digest_len, int sig_type,
    uint8_t *signature, int sig_len,
    uint8_t *modulus, int mod_len,
    uint8_t *pub_exp, int pub_exp_len)
{

    int ret = X509_OK;

    BI_CTX *bi_ctx = bi_initialize();
    bigint *bi_digest = bi_import(bi_ctx, digest, digest_len);
    bigint *mod = bi_import(bi_ctx, modulus, mod_len);
    bigint *expn = bi_import(bi_ctx, pub_exp, pub_exp_len);
    bigint *cert_sig = NULL;

    /* check the signature */
    cert_sig = sig_verify(bi_ctx, signature, sig_len, sig_type,
                        bi_clone(bi_ctx, mod), bi_clone(bi_ctx, expn));

    if (cert_sig && bi_digest)
    {
        if (bi_compare(cert_sig, bi_digest) != 0)
            ret = X509_VFY_ERROR_BAD_SIGNATURE;


        bi_free(bi_ctx, cert_sig);
    }
    else
    {
        ret = X509_VFY_ERROR_BAD_SIGNATURE;
    }

    if (ret)
        goto end_verify;

end_verify:
    return ret;
}

void printBuf( uint8_t *buf, size_t buf_len )
{
    for (int i = 0; i < buf_len; i++)
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

    int ret = 0;

    /* this would be our message digest */
    uint8_t helloworldSHA256Bytes[] = {
        0x75, 0x09, 0xe5, 0xbd, 0xa0, 0xc7, 0x62, 0xd2, 0xba, 0xc7, 0xf9, 0x0d,
        0x75, 0x8b, 0x5b, 0x22, 0x63, 0xfa, 0x01, 0xcc, 0xbc, 0x54, 0x2a, 0xb5,
        0xe3, 0xdf, 0x16, 0x3b, 0xe0, 0x8e, 0x6c, 0xa9       
    };

    /* if the low-exponent attk is successful, this should not matter */
    uint8_t modulusBytes[] = {
        0xe9, 0x32, 0xac, 0x92, 0x25, 0x2f, 0x58, 0x5b, 0x3a, 0x80, 0xa4, 0xdd,
        0x76, 0xa8, 0x97, 0xc8, 0xb7, 0x65, 0x29, 0x52, 0xfe, 0x78, 0x8f, 0x6e,
        0xc8, 0xdd, 0x64, 0x05, 0x87, 0xa1, 0xee, 0x56, 0x47, 0x67, 0x0a, 0x8a,
        0xd4, 0xc2, 0xbe, 0x0f, 0x9f, 0xa6, 0xe4, 0x9c, 0x60, 0x5a, 0xdf, 0x77,
        0xb5, 0x17, 0x42, 0x30, 0xaf, 0x7b, 0xd5, 0x0e, 0x5d, 0x6d, 0x6d, 0x6d,
        0x28, 0xcc, 0xf0, 0xa8, 0x86, 0xa5, 0x14, 0xcc, 0x72, 0xe5, 0x1d, 0x20,
        0x9c, 0xc7, 0x72, 0xa5, 0x2e, 0xf4, 0x19, 0xf6, 0xa9, 0x53, 0xf3, 0x13,
        0x59, 0x29, 0x58, 0x8e, 0xbe, 0x9b, 0x35, 0x1f, 0xca, 0x61, 0xce, 0xd7,
        0x8f, 0x34, 0x6f, 0xe0, 0x0d, 0xbb, 0x63, 0x06, 0xe5, 0xc2, 0xa4, 0xc6,
        0xdf, 0xc3, 0x77, 0x9a, 0xf8, 0x5a, 0xb4, 0x17, 0x37, 0x1c, 0xf3, 0x4d,
        0x83, 0x87, 0xb9, 0xb3, 0x0a, 0xe4, 0x6d, 0x7a, 0x5f, 0xf5, 0xa6, 0x55,
        0xb8, 0xd8, 0x45, 0x5f, 0x1b, 0x94, 0xae, 0x73, 0x69, 0x89, 0xd6, 0x0a,
        0x6f, 0x2f, 0xd5, 0xca, 0xdb, 0xff, 0xbd, 0x50, 0x4c, 0x5a, 0x75, 0x6a,
        0x2e, 0x6b, 0xb5, 0xce, 0xcc, 0x13, 0xbc, 0xa7, 0x50, 0x3f, 0x6d, 0xf8,
        0xb5, 0x2a, 0xce, 0x5c, 0x41, 0x09, 0x97, 0xe9, 0x88, 0x09, 0xdb, 0x4d,
        0xc3, 0x0d, 0x94, 0x3d, 0xe4, 0xe8, 0x12, 0xa4, 0x75, 0x53, 0xdc, 0xe5,
        0x48, 0x44, 0xa7, 0x8e, 0x36, 0x40, 0x1d, 0x13, 0xf7, 0x7d, 0xc6, 0x50,
        0x61, 0x9f, 0xed, 0x88, 0xd8, 0xb3, 0x92, 0x6e, 0x3d, 0x8e, 0x31, 0x9c,
        0x80, 0xc7, 0x44, 0x77, 0x9a, 0xc5, 0xd6, 0xab, 0xe2, 0x52, 0x89, 0x69,
        0x50, 0x91, 0x74, 0x76, 0xec, 0xe5, 0xe8, 0xfc, 0x27, 0xd5, 0xf0, 0x53,
        0xd6, 0x01, 0x8d, 0x91, 0xb5, 0x02, 0xc4, 0x78, 0x75, 0x58, 0xa0, 0x02,
        0xb9, 0x28, 0x3d, 0xa7
    };

    /* low-exponent ... let's say 3 */
    uint8_t pubExpBytes[] = {
        0x03
    };

    if(argc != 2)
    {
        printf("usage: %s <signature-hex-string>\n", argv[0]);
    	return 0;
    }
    
    size_t siglen;
    uint8_t *sig = datahex(argv[1], &siglen);

    ret = x509_verify_mimic(helloworldSHA256Bytes, sizeof(helloworldSHA256Bytes), SIG_TYPE_SHA256,
            sig, siglen,
            modulusBytes, sizeof(modulusBytes),
            pubExpBytes, sizeof(pubExpBytes)
    );

    if (! ret) {
		printf("ret = 0\n");
	} else {
		printf("ret = -1\n");
	}

    return 0;
}

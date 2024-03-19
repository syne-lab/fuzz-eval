#define DEBUG
#include <stdlib.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "pluto/defs.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswcrypto.h"
#include "secrets.h"
#include "packet.h"
#include "id.h"
#include "state.h"
#include "pluto/keys.h"

#include "hexdump.c"

extern err_t try_RSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN]
                                  , size_t hash_len
                                  , const pb_stream *sig_pbs, struct pubkey *kr
                                  , struct state *st);

void
whack_log(int mess_no, const char *message, ...){}

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

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

/* based on err_t try_RSA_signature_v2() */
int verify_signature(
    struct pubkey *k,
    struct state *st,
    uint8_t *hash_val, 
    size_t hash_len,
    uint8_t *sig_val,
    size_t sig_len)
{
    int ret = 0;
    pb_stream sig_pbs;
    sig_pbs.cur = sig_val;
    sig_pbs.roof = sig_val+sig_len;
    err_t e = NULL;

    e = try_RSA_signature_v2(
            hash_val,    // const u_char hash_val[MAX_DIGEST_LEN]
		    hash_len,    // size_t hash_len
		    &sig_pbs,    // const pb_stream *sig_pbs
            k,           // struct pubkey *kr
		    st           // struct state *st
        );

    if (e == NULL)
        ret = 0;
    else
        ret = -1;

    // u_char s[RSA_MAX_OCTETS];	/* for decrypted sig_val */
    // u_char *sig;
    // err_t e = NULL;

    // if (k == NULL)
	// return 1;	/* failure: no key to use */

    // /* decrypt the signature -- reversing RSA_sign_hash */
    // if (sig_len != k->k)
    // {
    //     DBG_log("sig_len: %u != k->k: %u"
    //             , (unsigned int)sig_len, (unsigned int)k->k);
	// return 1;
    // }

    // if((e = verify_signed_hash(k, s, sizeof(s), &sig, hash_len+der_digestinfo_len,
    //                            sig_val, sig_len)) != NULL) {
    //     return -1;
    // }

    // /* 2 verify that the has was done with SHA1 */
    // if(memcmp(der_digestinfo, sig, der_digestinfo_len)!=0) {
	// return 8;
    // }
    // sig += der_digestinfo_len;

    // DBG(DBG_CRYPT,
	// DBG_dump("v2rsa decrypted SIG:", sig,      hash_len);
	// DBG_dump("v2rsa computed hash:", hash_val, hash_len);
    // );

    // if(memcmp(sig, hash_val, hash_len) != 0) {
	// return 9;
    // }

    return ret;
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
    int i;
    struct id one;

    load_oswcrypto();

    progname = argv[0];

    // tool_init_log();

    // set_debugging(DBG_CONTROL|DBG_CRYPT);

    int ret;

    /* this would be our message digest */
    uint8_t helloworldSHA1Bytes[] = {
        0x43, 0x0c, 0xe3, 0x4d, 0x02, 0x07, 0x24, 0xed, 0x75, 0xa1, 0x96, 0xdf,
        0xc2, 0xad, 0x67, 0xc7, 0x77, 0x72, 0xd1, 0x69       
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

    /* prepare the public key */
    struct pubkey pk;
    pk.u.rsa.k = sizeof(modulusBytes);
    n_to_mpz(&(pk.u.rsa.e), pubExpBytes, sizeof(pubExpBytes));
    n_to_mpz(&(pk.u.rsa.n), modulusBytes, sizeof(modulusBytes));
    /* prepare a place holder state */
    struct state st;
    memset(&st, 0, sizeof(struct state));

    size_t siglen;
    uint8_t *sig = datahex(argv[1], &siglen);


    ret = verify_signature(
        &pk,
        &st,
        helloworldSHA1Bytes, sizeof(helloworldSHA1Bytes), 
        sig, siglen
    );

    printf("ret = %d\n", ret);

    exit(0);
}

// validat9.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptlib.h"
#include "cpu.h"

#include "asn.h"
#include "oids.h"

#include "sha.h"
#include "sha3.h"

#include "rsa.h"
#include "pubkey.h"

#include <iostream>
#include <iomanip>
#include <sstream>

#include <stdint.h>

// datahex reads hex string and returns bytes array
CryptoPP::byte* datahex(char* string, size_t &dlength) {

    if(string == NULL) 
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0)
       return NULL;

    dlength = slength / 2;

    CryptoPP::byte* data = (CryptoPP::byte*) malloc(dlength);
    memset(data, 0, dlength);

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

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

bool ValidateRSA_Sign(byte* signature, size_t &signatureLength)
{
	bool pass = true, fail;
	{
		const char plain[] = "hello world!";

		Integer n("0xe932ac92252f585b3a80a4dd76a897c8b7652952fe788f6ec8dd640587a1ee5647670a8ad4c2be0f9fa6e49c605adf77b5174230af7bd50e5d6d6d6d28ccf0a886a514cc72e51d209cc772a52ef419f6a953f3135929588ebe9b351fca61ced78f346fe00dbb6306e5c2a4c6dfc3779af85ab417371cf34d8387b9b30ae46d7a5ff5a655b8d8455f1b94ae736989d60a6f2fd5cadbffbd504c5a756a2e6bb5cecc13bca7503f6df8b52ace5c410997e98809db4dc30d943de4e812a47553dce54844a78e36401d13f77dc650619fed88d8b3926e3d8e319c80c744779ac5d6abe252896950917476ece5e8fc27d5f053d6018d91b502c4787558a002b9283da7"), e("0x3");

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

		RSASS<PKCS1v15, SHA256>::Verifier rsaPub(pubKey);
				
		fail = !rsaPub.VerifyMessage((byte *)plain, strlen(plain), signature, signatureLength);

        if (fail) {
            printf("ret = -1\n");
        } else {
            printf("ret = 0\n");
        }
	}

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

int main(int argc, char **argv) 
{

    if(argc != 2){
        printf("usage: %s <signature-hex-string>\n", argv[0]);
    	return -2;
    }


    size_t sigLen = 0;
    CryptoPP::byte* signature = datahex(argv[1], sigLen);

    return CryptoPP::Test::ValidateRSA_Sign(signature, sigLen);

}
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>

#include <stdint.h>

// datahex reads hex string and returns bytes array
uint8_t* datahex(char* string, size_t &dlength) {

    if(string == NULL) 
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0)
       return NULL;

    dlength = slength / 2;

    uint8_t* data = (uint8_t*) malloc(dlength);
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


int main(int argc, char **argv) 
{

    if(argc != 2){
        printf("usage: %s <signature-hex-string>\n", argv[0]);
    	return -2;
    }

    // Botan::AutoSeeded_RNG rng; 
    // Botan::RSA_PrivateKey key(rng, 4096);

    std::string msg("hello world!");
    std::vector<uint8_t> data(msg.data(),msg.data()+msg.length());
    
    Botan::BigInt n("0xe932ac92252f585b3a80a4dd76a897c8b7652952fe788f6ec8dd640587a1ee5647670a8ad4c2be0f9fa6e49c605adf77b5174230af7bd50e5d6d6d6d28ccf0a886a514cc72e51d209cc772a52ef419f6a953f3135929588ebe9b351fca61ced78f346fe00dbb6306e5c2a4c6dfc3779af85ab417371cf34d8387b9b30ae46d7a5ff5a655b8d8455f1b94ae736989d60a6f2fd5cadbffbd504c5a756a2e6bb5cecc13bca7503f6df8b52ace5c410997e98809db4dc30d943de4e812a47553dce54844a78e36401d13f77dc650619fed88d8b3926e3d8e319c80c744779ac5d6abe252896950917476ece5e8fc27d5f053d6018d91b502c4787558a002b9283da7"), e(3);

    Botan::RSA_PublicKey pubk(n, e);
    
    // Botan::BigInt p("172300294258235936778332706443534030586278975352217688534546472022499838586156176041941991855520353445866151970518169735351148411224210831949849205285740989137244052855063754898755504850490262243204644021984231479429770037232758676043409626240347002715161861687542292053974582547285043983272585345101081717229"), q("170855850921959232253781871827685791673962454254372190565963117985751576779984807568391697150824651809760412933498107110417977147984545439953476233395492916752776227386607023982598455624772620825559200945379405646172359576435586073183845429014814793422943156879029641994501029668043503294757006391397998183267");

    // Botan::RSA_PrivateKey privk(p, q, e);
    // Botan::PK_Signer signer(privk, rng, "EMSA3(SHA-256)");
    // signer.update(data);
    // std::vector<uint8_t> signature = signer.signature(rng);
    // std::cout << "Signature:" << std::endl << Botan::hex_encode(signature) << std::endl;

    // verify signature
    Botan::PK_Verifier verifier(pubk, "EMSA3(SHA-256)");

    size_t sigLen;
    uint8_t* sig = datahex(argv[1], sigLen);
    std::vector<uint8_t> sigv(sig, sig+sigLen);
    std::cout << (verifier.verify_message(data, sigv)? "ret = 0" : "ret = -1") << std::endl;

    free(sig);

    return 0;
}
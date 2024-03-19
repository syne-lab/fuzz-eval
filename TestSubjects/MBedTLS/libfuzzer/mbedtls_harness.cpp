#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <iostream>
#include <python3.10/Python.h>
#include <csignal>

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

#define min(m_a, m_b) (((m_a) < (m_b)) ? (m_a) : (m_b))
unsigned char *read_file_contents(char *filename, int file_size)
{
    FILE *fp;
    unsigned char *file_contents = (unsigned char *)malloc(file_size);
    if (file_contents == NULL)
    {
        fprintf(stderr, "Memory error: unable to allocate %d bytes\n", file_size);
        return NULL;
    }

    fp = fopen(filename, "rt");
    if (fp == NULL)
    {
        fprintf(stderr, "Unable to open %s\n", filename);
        fclose(fp);
        free(file_contents);
        return NULL;
    }
    if (fread(file_contents, file_size, 1, fp) != 1)
    {
        fprintf(stderr, "Unable t read content of %s\n", filename);
        fclose(fp);
        free(file_contents);
        return NULL;
    }
    fclose(fp);
    return file_contents;
}

void printBuf(uint8_t *buf, size_t buf_len)
{
    for (size_t i = 0; i < buf_len; i++)
    {
        printf("%02hhx ", buf[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
        else if ((i + 1) % 16 == 0)
            printf(" ");
    }
    printf("\n");
}

// datahex reads hex string and returns bytes array
uint8_t *datahex(char *string, size_t *dlength)
{

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0)
        return NULL;

    *dlength = slength / 2;

    uint8_t *data = (uint8_t *)malloc(*dlength);
    memset(data, 0, *dlength);

    size_t index = 0;
    while (index < slength)
    {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
        {
            free(data);
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

/* Cyiu: this is to load a modulus and exponent of our choosing
  into a mbedTLS RSA public key structure */
int32_t loadPublicKey(mbedtls_pk_context *pk,
                      uint8_t *modulus, int mod_len,
                      uint8_t *pub_exp, int pub_exp_len)
{
    /* the followings are inspired by mbedtls_pk_parse_key() */
    int ret;
    const mbedtls_pk_info_t *pk_info;

    mbedtls_pk_init(pk);

    if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == NULL)
        return (MBEDTLS_ERR_PK_UNKNOWN_PK_ALG);

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0)
    {
        mbedtls_pk_free(pk);
    }

    /* the followings are inspired by pk_parse_key_pkcs1_der()
        and mbedtls_asn1_get_mpi() */
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
    rsa->ver = 0;

    mbedtls_mpi_read_binary(&rsa->N, modulus, mod_len);
    mbedtls_mpi_read_binary(&rsa->E, pub_exp, pub_exp_len);

    rsa->len = mod_len;
    rsa->padding = MBEDTLS_RSA_PKCS_V15;

    return 0;
}

/* Cyiu: this is to invoke the signature verification function */
int verify_signature(mbedtls_pk_context *pk,
                     uint8_t *hash,
                     size_t hash_len,
                     uint8_t *sig)
{
    int ret = 0;
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);

    ret = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL,
                                   MBEDTLS_RSA_PUBLIC,
                                   MBEDTLS_MD_SHA256,
                                   hash_len, hash, sig);

    return ret;
}

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string hexStr2(unsigned char *data, int len)
{
    std::string s(len * 2, ' ');
    for (int i = 0; i < len; ++i)
    {
        s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
    return s;
}

sig_atomic_t signaled = 0;

int mod_len = 256;
string hexRep;

bool isValid()
{
    Py_Initialize();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('/MorpheusScripts')");
    PyObject *name, *load_module, *func, *callfunc, *args;
    name = PyUnicode_FromString((char *)"validator_pkcs");
    load_module = PyImport_Import(name);
    func = PyObject_GetAttrString(load_module, (char *)"isValid");

    args = PyTuple_Pack(2, PyUnicode_FromString(hexRep.c_str()), PyFloat_FromDouble((double)mod_len));

    callfunc = PyObject_CallObject(func, args);
    bool valid = PyObject_IsTrue(callfunc);

    // cout<<valid<<endl;
    Py_Finalize();
    return valid;
}

int status, valread, client_fd;
struct sockaddr_in serv_addr;
void my_handler(int signum)
{
    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0)
    {
        printf("\nConnection Failed \n");
    }

    hexRep += ",";
    hexRep += "-1"; // indicates that the library crashed!!
    send(client_fd, hexRep.c_str(), hexRep.size(), 0);
    close(client_fd);
    exit(0);
}

void register_custom_handler()
{
    signal(SIGABRT, my_handler);
    signal(SIGFPE, my_handler);
    signal(SIGILL, my_handler);
    signal(SIGINT, my_handler);
    signal(SIGSEGV, my_handler);
    signal(SIGTERM, my_handler);
}

void unregister_custom_handler()
{
    signal(SIGABRT, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
}

int PORTNUM;
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    printf("Received %d args\n", *argc);
    int foundServer = 0;
    for(int i=0;i<(*argc);i++)
    {
        printf("argv %d is --> %s\n", i+1, (*argv)[i]);
        char *curArg = (*argv)[i];
        if(strlen(curArg)>=2){
            if(curArg[0] == '-' && curArg[1] =='-')
            {
                printf("Found Port Number: %s\n", curArg);
                curArg[0] = '0';
                curArg[1] = '0';
                PORTNUM = atoi(curArg);
                curArg[0]='-';
                curArg[1]='-';
                foundServer = 1;
                break;
            }
        }
    }
    if(foundServer){
        printf("Server located at: %d\n", PORTNUM);
    }
    else{
        printf("Server not found! Aborting.....\n");
        abort();
    }
 return 0;
}




extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    
    assert(Size<=512);

  // Step 0 >> Reigster for handling signals
  register_custom_handler();

  // Step 1 >> Take a file name as an input, read the file in binary mode
  // if (argc != 3)
  // {
  //   printf("usage: %s <file containing the EM structure in binary> <port number of the server running on localhost>\n", argv[0]);
  //   return 0;
  // }

  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }
  int portnum = PORTNUM;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portnum);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
  {
    printf(
        "\nInvalid address/ Address not supported \n");
    return -1;
  }
  //-------------------------------------------------------------------------------------

  // Step 2 >> Convert the binary file contents to hex string
  hexRep = hexStr2((unsigned char*)Data, (int)Size);

    // Step 3 >> Compute the signature using python script

    Py_Initialize();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('/MorpheusScripts')");
    PyObject *name, *load_module, *func, *callfunc, *args;
    name = PyUnicode_FromString((char *)"script");
    load_module = PyImport_Import(name);
    func = PyObject_GetAttrString(load_module, (char *)"generate_signature");
    args = PyTuple_Pack(1, PyUnicode_FromString(hexRep.c_str()));

    callfunc = PyObject_CallObject(func, args);
    string sig_str = std::string(PyUnicode_AsUTF8(callfunc));

    Py_Finalize();

    // Step 4 >> feed the computed signature to Morpheus's test harness
    /******************************************************************************************************************************************/

    /* this would be our message digest */
    size_t siglen;
    uint8_t *sig = datahex(const_cast<char *>(sig_str.c_str()), &siglen); // CHANGE: argv[1] -> sig_str.c_str()

    int ret;

    /* this would be our message digest */
    uint8_t helloworldSHA256Bytes[] = {
        0x75, 0x09, 0xe5, 0xbd, 0xa0, 0xc7, 0x62, 0xd2, 0xba, 0xc7, 0xf9, 0x0d,
        0x75, 0x8b, 0x5b, 0x22, 0x63, 0xfa, 0x01, 0xcc, 0xbc, 0x54, 0x2a, 0xb5,
        0xe3, 0xdf, 0x16, 0x3b, 0xe0, 0x8e, 0x6c, 0xa9};

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
        0xb9, 0x28, 0x3d, 0xa7};

    /* low-exponent ... let's say 3 */
    uint8_t pubExpBytes[] = {
        0x03};

    mbedtls_pk_context PublicKey;

    ret = loadPublicKey(&PublicKey, modulusBytes, sizeof(modulusBytes), pubExpBytes, sizeof(pubExpBytes));
    if (ret != 0)
    {
        printf("loadPublicKey failed: error %d\n", ret);
        exit(ret);
    }

    ret = verify_signature(&PublicKey, helloworldSHA256Bytes, sizeof(helloworldSHA256Bytes), sig);
    
    int success = 0;
    if(ret == 0){
        success = 1;
    }
    if (success)
    {
        printf("Parsing Successful!\n");
    }

    // Step 5 >> unregister custom
    unregister_custom_handler();
    // printf("Validation Result: %d\n", ret);
    /******************************************************************************************************************************************/

    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    hexRep += ",";
    hexRep += to_string(success);
    send(client_fd, hexRep.c_str(), hexRep.size(), 0);
    close(client_fd);
    // free(file_contents);
    free(sig);

    return 0;
}

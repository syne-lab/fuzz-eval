#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "library.h"
#include "utils/debug.h"
#include "utils/chunk.h"
#include "utils/backtrace.h"
#include "collections/array.h"
#include "plugins/plugin_feature.h"
#include "credentials/keys/signature_params.h"

#include "plugins/pkcs1/pkcs1_builder.h"

#include <signal.h>
#include <python3.10/Python.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* inspired by test_rsa.c of the test suite of libstrongswan */
int verify_signature(
    public_key_t *pubkey,
    uint8_t *data_val,
    size_t data_len,
    uint8_t *sig_val,
    size_t sig_len)
{
    int ret = 0;

    /* prepare our input in the libstrongswan-style "chunk" type */
    chunk_t sig_chunk, data_chunk;
    sig_chunk.ptr = sig_val;
    sig_chunk.len = sig_len;
    data_chunk.ptr = data_val;
    data_chunk.len = data_len;

    ret = pubkey->verify(pubkey, SIGN_RSA_EMSA_PKCS1_SHA2_256, NULL, data_chunk, sig_chunk);

    return ret;
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

    uint8_t *data = malloc(*dlength);
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

public_key_t *parse_key(int zero, ...)
{

    public_key_t *pk = NULL;

    va_list keyargs;

    va_start(keyargs, zero);
    pk = pkcs1_public_key_load(KEY_RSA, keyargs);
    va_end(keyargs);

    return pk;
}

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

sig_atomic_t signaled = 0;

int mod_len = 256;
char *hexRep;
int hexRepLen;

char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
char *hexStr2(unsigned char *data, int len)
{

    char *s = (char *)malloc((2 * len * sizeof(char)) + 1);

    for (int i = 0; i < len; ++i)
    {
        s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
    s[2 * len] = '\0';

    return s;
}


void adjustHexRep(char comma, char retVal)
{
    char *tmp = (char *)malloc(sizeof(char) * (hexRepLen + 3));
    for (int i = 0; i < hexRepLen; i++)
    {
        tmp[i] = hexRep[i];
    }
    tmp[hexRepLen] = comma;
    tmp[hexRepLen + 1] = retVal;
    tmp[hexRepLen + 2] = '\0';
    free(hexRep);
    hexRep = tmp;
    hexRepLen = strlen(hexRep);
}

int status, valread, client_fd;
struct sockaddr_in serv_addr;
void my_handler(int signum)
{
    printf("SIGNALED: %d\n", signum);
    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0)
    {
        printf("\nConnection Failed \n");
        // return -1;
    }

    adjustHexRep(',', '9');
    // hexRep+="9"; // indicates that the library crashed!!
    send(client_fd, hexRep, hexRepLen, 0);
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

int main(int argc, char *argv[])
{

    // Step 0 >> Reigster for handling signals
    register_custom_handler();

    // Step 1 >> Take a file name as an input, read the file in binary mode
    if (argc != 3)
    {
        printf("usage: %s <file containing the EM structure in binary> <port number of the server running on localhost>\n", argv[0]);
        return 0;
    }

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    int portnum = atoi(argv[2]);
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

    // freopen("output.txt", "a", stdout);
    char *filename;
    struct stat filestatus;
    int file_size;
    unsigned char *file_contents;

    filename = argv[1];
    if (stat(filename, &filestatus) != 0)
    {
        fprintf(stderr, "File %s not found\n", filename);
        printf("--------------\n");
        return 1;
    }
    file_size = filestatus.st_size;
    file_contents = read_file_contents(filename, file_size);
    if (file_contents == NULL)
    {
        printf("--------------\n");
        return 1;
    }

    // Step 2 >> Convert the binary file contents to hex string
    hexRep = hexStr2(file_contents, file_size);
    hexRepLen = strlen(hexRep);

    // Step 3 >> Compute the signature using python script

    Py_Initialize();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('/MorpheusScripts')");
    PyObject *name, *load_module, *func, *callfunc, *args;
    name = PyUnicode_FromString((char *)"script");
    load_module = PyImport_Import(name);
    func = PyObject_GetAttrString(load_module, (char *)"generate_signature");
    args = PyTuple_Pack(1, PyUnicode_FromString(hexRep));

    callfunc = PyObject_CallObject(func, args);
    char *sig_str = (char *)PyUnicode_AsUTF8(callfunc);
    printf("SIGNATURE LENGTH: %d\n", strlen(sig_str));

    Py_Finalize();

    printf("SIGNATURE: %s\n", sig_str);

    int ret;

    library_init("emptyconf", "pkcs1");

    // /* guess we have to load plugins before any meaningful testing */
    if (!lib->plugins->load(lib->plugins, "aes des rc2 sha2 sha1 md5 mgf1 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem fips-prf gmp curve25519 xcbc cmac hmac"))
    {
        printf("error loading plugins\n");
        return -1;
    }

    uint8_t helloworldBytes[] = {
        'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};

    /* prepare the public key */
    public_key_t *pubkey;

    uint8_t keyder[] = {
        0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe9, 0x32, 0xac,
        0x92, 0x25, 0x2f, 0x58, 0x5b, 0x3a, 0x80, 0xa4, 0xdd, 0x76, 0xa8, 0x97,
        0xc8, 0xb7, 0x65, 0x29, 0x52, 0xfe, 0x78, 0x8f, 0x6e, 0xc8, 0xdd, 0x64,
        0x05, 0x87, 0xa1, 0xee, 0x56, 0x47, 0x67, 0x0a, 0x8a, 0xd4, 0xc2, 0xbe,
        0x0f, 0x9f, 0xa6, 0xe4, 0x9c, 0x60, 0x5a, 0xdf, 0x77, 0xb5, 0x17, 0x42,
        0x30, 0xaf, 0x7b, 0xd5, 0x0e, 0x5d, 0x6d, 0x6d, 0x6d, 0x28, 0xcc, 0xf0,
        0xa8, 0x86, 0xa5, 0x14, 0xcc, 0x72, 0xe5, 0x1d, 0x20, 0x9c, 0xc7, 0x72,
        0xa5, 0x2e, 0xf4, 0x19, 0xf6, 0xa9, 0x53, 0xf3, 0x13, 0x59, 0x29, 0x58,
        0x8e, 0xbe, 0x9b, 0x35, 0x1f, 0xca, 0x61, 0xce, 0xd7, 0x8f, 0x34, 0x6f,
        0xe0, 0x0d, 0xbb, 0x63, 0x06, 0xe5, 0xc2, 0xa4, 0xc6, 0xdf, 0xc3, 0x77,
        0x9a, 0xf8, 0x5a, 0xb4, 0x17, 0x37, 0x1c, 0xf3, 0x4d, 0x83, 0x87, 0xb9,
        0xb3, 0x0a, 0xe4, 0x6d, 0x7a, 0x5f, 0xf5, 0xa6, 0x55, 0xb8, 0xd8, 0x45,
        0x5f, 0x1b, 0x94, 0xae, 0x73, 0x69, 0x89, 0xd6, 0x0a, 0x6f, 0x2f, 0xd5,
        0xca, 0xdb, 0xff, 0xbd, 0x50, 0x4c, 0x5a, 0x75, 0x6a, 0x2e, 0x6b, 0xb5,
        0xce, 0xcc, 0x13, 0xbc, 0xa7, 0x50, 0x3f, 0x6d, 0xf8, 0xb5, 0x2a, 0xce,
        0x5c, 0x41, 0x09, 0x97, 0xe9, 0x88, 0x09, 0xdb, 0x4d, 0xc3, 0x0d, 0x94,
        0x3d, 0xe4, 0xe8, 0x12, 0xa4, 0x75, 0x53, 0xdc, 0xe5, 0x48, 0x44, 0xa7,
        0x8e, 0x36, 0x40, 0x1d, 0x13, 0xf7, 0x7d, 0xc6, 0x50, 0x61, 0x9f, 0xed,
        0x88, 0xd8, 0xb3, 0x92, 0x6e, 0x3d, 0x8e, 0x31, 0x9c, 0x80, 0xc7, 0x44,
        0x77, 0x9a, 0xc5, 0xd6, 0xab, 0xe2, 0x52, 0x89, 0x69, 0x50, 0x91, 0x74,
        0x76, 0xec, 0xe5, 0xe8, 0xfc, 0x27, 0xd5, 0xf0, 0x53, 0xd6, 0x01, 0x8d,
        0x91, 0xb5, 0x02, 0xc4, 0x78, 0x75, 0x58, 0xa0, 0x02, 0xb9, 0x28, 0x3d,
        0xa7, 0x02, 0x01, 0x03};
    chunk_t keyblob;
    keyblob.ptr = keyder;
    keyblob.len = sizeof(keyder);

    pubkey = parse_key(0, BUILD_BLOB_ASN1_DER, keyblob, BUILD_END);


    size_t siglen;
    uint8_t *sig = datahex(sig_str, &siglen);

    ret = verify_signature(
        pubkey,
        helloworldBytes, sizeof(helloworldBytes),
        sig, siglen);

    int result = 9;
    if (ret == 1)
    {
        printf("ret = 0\n");
        result = 1;
    }
    else
    {
        printf("ret = -1\n");
        result = 0;
    }

    /******************************************************************************************************************************************/

    if (result == 1)
    {
        printf("Parsing Successful!\n");
    }

    // Step 5 >> unregister custom
    unregister_custom_handler();
    printf("Validation Result: %d\n", ret);

    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                          sizeof(serv_addr))) < 0)
    {
        printf("\nConnection Failed \n");
        goto cleanup;
    }

    adjustHexRep(',', (char)('0' + result));

    send(client_fd, hexRep, hexRepLen, 0);
    close(client_fd);
    
cleanup:
    free(file_contents);
    free(sig);
    free(hexRep);

    
    return 0;
}

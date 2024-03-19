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

#include <signal.h>
#include <python3.10/Python.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

int verify_signature(
    RSA *pubkey,
    uint8_t *hash, 
    size_t hash_len,
    uint8_t *sig,
    size_t sig_len)
{
    int ret = 0;

    ret = RSA_verify(NID_sha256, hash, hash_len, sig, sig_len, pubkey);

    // ERR_print_errors_fp(stdout);

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

    uint8_t* data = malloc(*dlength);
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


    fclose(stderr);
    // stderr = fopen("/dev/null","w");


    size_t siglen;
    uint8_t *sig = datahex(sig_str, &siglen);

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

    BIO *pkbio = BIO_new_mem_buf(pubkeyPEM, sizeof(pubkeyPEM));
    assert(pkbio != NULL);

    RSA *pubkey = PEM_read_bio_RSAPublicKey(pkbio, NULL, 0, NULL);
    assert(pubkey != NULL);

    /* this would be our message digest */
    uint8_t helloworldSHA256Bytes[] = {
        0x75, 0x09, 0xe5, 0xbd, 0xa0, 0xc7, 0x62, 0xd2, 0xba, 0xc7, 0xf9, 0x0d,
        0x75, 0x8b, 0x5b, 0x22, 0x63, 0xfa, 0x01, 0xcc, 0xbc, 0x54, 0x2a, 0xb5,
        0xe3, 0xdf, 0x16, 0x3b, 0xe0, 0x8e, 0x6c, 0xa9       
    };

    ret = verify_signature(
        pubkey,
        helloworldSHA256Bytes, sizeof(helloworldSHA256Bytes), 
        sig, siglen
    );

    int result = 9;
    if (ret) {
        printf("ret = 0\n");
        result = 1;
    } else {
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
    
cleanup:
    close(client_fd);
    free(file_contents);
    free(sig);
    free(hexRep);


    return 0;
}


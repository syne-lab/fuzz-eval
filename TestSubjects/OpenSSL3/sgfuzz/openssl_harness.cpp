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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <iostream>
#include <python3.8/Python.h>
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

    hexRep+=",";
    hexRep+="-1"; // indicates that the library crashed!!
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
    uint8_t *sig = datahex(const_cast<char *>(sig_str.c_str()), &siglen);

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

    if(ret){
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

    hexRep+=",";
    hexRep+=to_string(ret);
    send(client_fd, hexRep.c_str(), hexRep.size(), 0);
    close(client_fd);
    // free(file_contents);
    free(sig);

    return 0;
}

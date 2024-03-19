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

#include <signal.h>
#include <python3.10/Python.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
using namespace std;
// uising namespace CryptoPP;

// datahex reads hex string and returns bytes array

// NAMESPACE_BEGIN(CryptoPP)
// NAMESPACE_BEGIN(Test)

// bool ValidateRSA_Sign(byte *signature, size_t &signatureLength)
// {
//   bool pass = true, fail;
//   {
//     const char plain[] = "hello world!";

//     Integer n("0xe932ac92252f585b3a80a4dd76a897c8b7652952fe788f6ec8dd640587a1ee5647670a8ad4c2be0f9fa6e49c605adf77b5174230af7bd50e5d6d6d6d28ccf0a886a514cc72e51d209cc772a52ef419f6a953f3135929588ebe9b351fca61ced78f346fe00dbb6306e5c2a4c6dfc3779af85ab417371cf34d8387b9b30ae46d7a5ff5a655b8d8455f1b94ae736989d60a6f2fd5cadbffbd504c5a756a2e6bb5cecc13bca7503f6df8b52ace5c410997e98809db4dc30d943de4e812a47553dce54844a78e36401d13f77dc650619fed88d8b3926e3d8e319c80c744779ac5d6abe252896950917476ece5e8fc27d5f053d6018d91b502c4787558a002b9283da7"), e("0x3");

//     RSA::PublicKey pubKey;
//     pubKey.Initialize(n, e);

//     RSASS<PKCS1v15, SHA256>::Verifier rsaPub(pubKey);

//     fail = !rsaPub.VerifyMessage((byte *)plain, strlen(plain), signature, signatureLength);

//     if (fail)
//     {
//       printf("ret = -1\n");
//     }
//     else
//     {
//       printf("ret = 0\n");
//     }

//     // Step 5 >> unregister custom
//     unregister_custom_handler();
//     printf("Validation Result: %d\n", ret);
//     /******************************************************************************************************************************************/

//     if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
//                           sizeof(serv_addr))) < 0)
//     {
//       printf("\nConnection Failed \n");
//       return -1;
//     }

//     hexRep += ",";
//     hexRep += to_string(ret);
//     send(client_fd, hexRep.c_str(), hexRep.size(), 0);
//     close(client_fd);
//     free(file_contents);
//   }

//   return pass;
// }

// NAMESPACE_END     // Test
//     NAMESPACE_END // CryptoPP



char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
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

int status, valread, client_fd;
struct sockaddr_in serv_addr;
void my_handler(int signum)
{
  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0)
  {
    printf("\nConnection Failed \n");
    // return -1;
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


CryptoPP::byte *datahex(char *string, size_t &dlength)
{

  if (string == NULL)
    return NULL;

  size_t slength = strlen(string);
  if ((slength % 2) != 0)
    return NULL;

  dlength = slength / 2;

  CryptoPP::byte *data = (CryptoPP::byte *)malloc(dlength);
  memset(data, 0, dlength);

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

  // freopen("output.txt", "a", stdout);
  // Step 2 >> Convert the binary file contents to hex string
  hexRep = hexStr2((unsigned char*) Data, (int)Size);

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

  cout << sig_str << endl;

  size_t sigLen = 0;
  CryptoPP::byte *signature = datahex((char*)sig_str.c_str(), sigLen);
  bool pass = true, fail;

  const char plain[] = "hello world!";

  CryptoPP::Integer n("0xe932ac92252f585b3a80a4dd76a897c8b7652952fe788f6ec8dd640587a1ee5647670a8ad4c2be0f9fa6e49c605adf77b5174230af7bd50e5d6d6d6d28ccf0a886a514cc72e51d209cc772a52ef419f6a953f3135929588ebe9b351fca61ced78f346fe00dbb6306e5c2a4c6dfc3779af85ab417371cf34d8387b9b30ae46d7a5ff5a655b8d8455f1b94ae736989d60a6f2fd5cadbffbd504c5a756a2e6bb5cecc13bca7503f6df8b52ace5c410997e98809db4dc30d943de4e812a47553dce54844a78e36401d13f77dc650619fed88d8b3926e3d8e319c80c744779ac5d6abe252896950917476ece5e8fc27d5f053d6018d91b502c4787558a002b9283da7"), e("0x3");

  CryptoPP::RSA::PublicKey pubKey;
  pubKey.Initialize(n, e);

  CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier rsaPub(pubKey);

  fail = !rsaPub.VerifyMessage((CryptoPP::byte *)plain, strlen(plain), signature, sigLen);
  int result = 9;
  if (fail)
  {
    printf("ret = -1\n");
    result = 0;
  }
  else
  {
    printf("ret = 0\n");
    result = 1;
  }

  // Step 5 >> unregister custom
  unregister_custom_handler();
  printf("Validation Result: %d\n", result);
  /******************************************************************************************************************************************/

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0)
  {
    printf("\nConnection Failed \n");
    goto cleanup;
  }

  hexRep += ",";
  hexRep += to_string(result);
  send(client_fd, hexRep.c_str(), hexRep.size(), 0);
  close(client_fd);
  

cleanup:
  if(signature != NULL)
    free(signature);

  return 0;
  // return CryptoPP::Test::ValidateRSA_Sign(signature, sigLen);
}
#ifdef __cplusplus
extern "C" {
#endif

#include "securechannel.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>


#define SIZE_BUF 4096
#define PASS_KEYSET_VERSION "AF"
#define ENC_KEYSET_VERSION "E0"
#define KEYSET_01_GP_KEY "404142434445464748494a4b4c4d4e4f"

//convert ascii characters to hex format
void asciiToHex(const char *s,char* s_hex);

//convert hex characters to ascii format
void hexToAscii(const char *s_hex,char* s);

//create a plug-up keyset PASS_KEYSET_VERSION from a password. So, a SC can be opened over this keyset giving this password.
int createPlugUpAccess(hid_device *h, const char *password);

//create a plug-up keyset ENC_KEYSET_VERSION with key role set to ENCRYPTION+DECRYPTION
int createEncryptionMasterKey(hid_device *h, char *encMasterKey);
//generate a strong 16-character password randomly
int generatePassword(char *password);

//create password from user 'input' or generate a one if input is left empty (input="")
int createPassword(const char *input, char *password);

//generate a GP key from a password using sha-1
int createGPKeyFromPass(const char *password, char *gpKey);

//encrypt/decrypt file
int fileEncryption(hid_device *h, const char *fileName, char *keyVersion, int encDec);

//open a SC giving a password, that mean that the keyset used was generated from this password.
int openSC_UsingPass(hid_device *h, char *keyset, const char *pass);

//Create a file encryption key : encryption master key diversified by a random file id
int createFileEncryptionKey(hid_device *h, char *masterKeyVersion, char *iv, char *fileID, char *fileEncryptionKey);

//used by fileEncryption() function : encrypt/decrypt file using AES_128_CBC
int do_crypt (const char *infile, const char *key_s, const char *iv_key_s, const char *iv_file_s, const char *fileId_s, int do_encrypt);

//delete keyset.. must be used over parent SC
int deleteKeyset(hid_device *h, char *keysetVersion);

//Check if the connected plug-up is an encryption one. returns 0 if not an encryption plug-up, 1 if it is or 2 if an other error occurs.
int isAnEncryptionPup(hid_device *h, char *passKeysetVersion);

//Retreive file encryption key from encrypted file
int retreiveFileEncryptionKeyFromEncryptedFile(hid_device *h, const char *fileName, char *keyVersion, char *fileEncryptionKey);

//Decrypt file using pass key (without a plug-up)
int fileDecryptionUsingPassKey(char *fileName, char *fileDecryptionKey);

#ifdef __cplusplus
}
#endif

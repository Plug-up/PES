/*
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/

#include "sc_functions.h"
#include "common.h"

FILE *flog;
char vtime2[30]="";


void generateChallenge(unsigned char *challenge,int chl_size){//OK

    int r = 0;

    r = RAND_bytes(challenge,chl_size);

    if (!r) {
        //printf("\ngenerateChallenge() error !\n");
        //exit(EXIT_FAILURE);
        printTime(vtime2);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ngenerateChallenge() error !\n",vtime2);
        fclose(flog);
        return;
    }

}



void computeCardCryptogram(char *hostChallenge,char *cardChallenge,char *counter,char *s_encKey, char *cardCryptogram){
    char temp[24*2+1]="";

    strcat(temp,hostChallenge);
    strcat(temp,counter);
    strcat(temp,cardChallenge);

    computeFull3DesMac(temp, s_encKey,cardCryptogram);

}

void computeHostCryptogram(char *hostChallenge,char *cardChallenge,char *counter,char *s_encKey,char *hostCryptogram){
    char temp[24*2+1]="";

    strcat(temp,counter);
    strcat(temp,cardChallenge);
    strcat(temp,hostChallenge);

    computeFull3DesMac(temp, s_encKey,hostCryptogram);

}


void computeFull3DesMac(char *data, char *key, char *full3DesMac)
{
    char pad[8*2+1]="8000000000000000",
         s_out[24*2+1]="";
    unsigned char bytes_data[24],out[24],
                  key1[8], key2[8],iv[8];
    des_key_schedule ks1,ks2;

    strcat(data,pad);

    stringToBytes(data,bytes_data);
    stringToBytes(str_sub(key,0,15), key1);
    stringToBytes(str_sub(key,16,31), key2);

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(bytes_data, out, (long) 24, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToString(out,24,s_out);

    strcpy(full3DesMac,str_sub(s_out,32,48));
}

void initializeUpdate(char *keysetId, char *hostChallenge, char* init_up_apdu){ //OK

    strcpy(init_up_apdu,"");

    strcat(init_up_apdu,"8050");
    strcat(init_up_apdu,keysetId);
    strcat(init_up_apdu,"0008");
    strcat(init_up_apdu,hostChallenge);
}

void computeSessionKey(char *counter,char *keyConstant, char *masterKey, char *s_sessionKey){ //OK

    char string_buf[16*2+1]="";
    unsigned char bytes_buf[16],
                  sessionKey[16];

    unsigned char key1[8], key2[8],iv[8];
    des_key_schedule ks1,ks2;

    strcat(string_buf,keyConstant);
    strcat(string_buf,counter);
    strcat(string_buf,"000000000000000000000000");

    stringToBytes(string_buf,bytes_buf);
    stringToBytes(str_sub(masterKey,0,15), key1);
    stringToBytes(str_sub(masterKey,16,31), key2);

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(bytes_buf, sessionKey, (long) 16, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToString(sessionKey,16,s_sessionKey);
}

int checkCardCryptogram(char *returnedCardCryptogram, char *computedCardCryptogram){
    int r;
    r=strcmp(returnedCardCryptogram,computedCardCryptogram);
    if(r==0) return 1; else return 0;
}

void modifyCdeForMac(char * command, char *mCommand){

    int i, t_bytes_cde = strlen(command)/2;
    unsigned char bytes_cde[260], bytes_mCde[260];

    stringToBytes(command,bytes_cde);

    for(i=0;i<t_bytes_cde;i++)
        bytes_mCde[i]=bytes_cde[i];

    bytes_mCde[0]=bytes_cde[0] | 0x04; //CLA ORed with 0x04
    bytes_mCde[4]=bytes_cde[4] + 0x08; //increased with C-MAC length

    bytesToString(bytes_mCde,t_bytes_cde,mCommand);

}

void computeRetailMac(const char *data, char *key, char *previousMac, char *retailMac)
{
    int i,l=0;
    char temp[(255+5+8)*2+1]= "";
    unsigned char work1[255+5],work2[8],work3[8],work4[255+5], out[8], zero_icv[8],
                  key1[8], key2[8];
    des_key_schedule ks1,ks2;

    memset(zero_icv,0,8);
    memset(work4,0,255+5);

    //*padding
    strcpy(temp,previousMac);
    strcat(temp,data);
    strcat(temp,"80");

    while(strlen(temp)%(8*2) != 0){
        strcat(temp,"00");
    }
    //*/

    l=strlen(temp);

    stringToBytes(str_sub(key,0,15), key1);

    //*simple des cbc using the first part of the key on L-8 temp bytes
    des_set_key((C_Block *)key1, ks1);

    stringToBytes(str_sub(temp,0,l-8*2-1),work1); //L-8 temp bytes

    des_ncbc_encrypt(work1,work4,(long)(l-8*2)/2,ks1,(C_Block *)zero_icv, DES_ENCRYPT);
    //*/

    stringToBytes(str_sub(temp,l-8*2,l-1),work2); //last 8 bytes of temp

    //*exclusive or between last 8 bytes of temp and the last block of the last simple DES
    for(i=0;i<8;i++){
        work3[i]= work2[i] ^ work4[i+l/2-16];
    }
    //*/

    //*triple DES ecb on the last result
    stringToBytes(str_sub(key,16,31), key2);

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    des_ecb3_encrypt((DES_cblock *)work3, (DES_cblock *)out, ks1,ks2,ks1, DES_ENCRYPT);

    //*/

    bytesToString(out,8,retailMac);

}

void externalAuthenticate(char *securityLevel, char *hostCryptogram, char *ext_auth_apdu){

    strcpy(ext_auth_apdu,"");

    strcat(ext_auth_apdu,"8082");
    strcat(ext_auth_apdu,securityLevel);
    strcat(ext_auth_apdu,"0008");
    strcat(ext_auth_apdu,hostCryptogram);
}

void diversifiedInitializeUpdate(char *keysetId, char *hostChallenge, char* masterKeyDiversifier, char* d_init_up_apdu){

    strcpy(d_init_up_apdu,"");

    strcat(d_init_up_apdu,"d050");
    strcat(d_init_up_apdu,keysetId);
    strcat(d_init_up_apdu,"1018");
    strcat(d_init_up_apdu,hostChallenge);
    strcat(d_init_up_apdu,masterKeyDiversifier);

}

void macedCommand(char *cde, char *cmacKey, char *lastMac, char *currentMac, char *macedCde){

    char mod_cde[260*2+1]="";

    strcpy(macedCde,"");

    modifyCdeForMac(cde,mod_cde);
    computeRetailMac(mod_cde,cmacKey,lastMac,currentMac);
    strcat(macedCde,mod_cde);
    strcat(macedCde,currentMac);

}

int createPutKeyCommand(char *numKeyset, char *mode, char *sdekKey, char* gp_enc, char *gp_mac, char *gp_dek, char *keyUsage, char *keyAccess, char *putKeyCommand){

    char putKeyCommand_temp[(255+5)*2+1]="",
         element1[2*2+1]="80d8",
         element2[1*2+1]="", //numKeyset
         element3[1*2+1]="", //mode
         element4[1*2+1]="55", //"58", //Lc
         element5[3*2+1]="ff8010", //key type + key length
         element6[16*2+1]="", //(GP-ENC) value, wrapped by session DEK
         element7[1*2+1]="03", //KCV length
         element8[3*2+1]="", //Key1 KCV
         element9[1*2+1]="01", //key usage length
         element10[1*2+1]="", //key usage
         element11[1*2+1]="02", //key access length
         element12[2*2+1]="", //key access
         element13[16*2+1]="", //(GP-MAC) value, wrapped by session fDEK
         element14[3*2+1]="", //Key2 KCV
         element15[16*2+1]="", //(GP-DEK) value, wrapped by session DEK
         element16[3*2+1]="", //Key3 KCV
         element17[10*2+1]=""; //Keyset diversifier value for a GlobalPlatform keyset

    strcpy(element2,numKeyset);
    strcpy(element3,mode);
    strcpy(element10,keyUsage);
    strcpy(element12,keyAccess);

    /*Encrypt gp-keys*/

    char tmp[8*2+1]="";

    //encrypt key1
    if(tripleDES_ECB_encrypt(str_sub(gp_enc,0,15),sdekKey,tmp))
        strcat(element6,tmp);
    else
        return 0;
    if(tripleDES_ECB_encrypt(str_sub(gp_enc,16,31),sdekKey,tmp))
        strcat(element6,tmp);
    else
        return 0;
    //encrypt key2
    if(tripleDES_ECB_encrypt(str_sub(gp_mac,0,15),sdekKey,tmp))
        strcat(element13,tmp);
    else
        return 0;
    if(tripleDES_ECB_encrypt(str_sub(gp_mac,16,31),sdekKey,tmp))
        strcat(element13,tmp);
    else
        return 0;
    //encrypt key3
    if(tripleDES_ECB_encrypt(str_sub(gp_dek,0,15),sdekKey,tmp))
        strcat(element15,tmp);
    else
        return 0;
    if(tripleDES_ECB_encrypt(str_sub(gp_dek,16,31),sdekKey,tmp))
        strcat(element15,tmp);
    else
        return 0;

    /*Compute KCVs*/

    //kcv1
    computeKCV(gp_enc,element8);
    //kcv2
    computeKCV(gp_mac,element14);
    //kcv3
    computeKCV(gp_dek,element16);

    //form the put key command
    strcat(putKeyCommand_temp,element1);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element3);
    strcat(putKeyCommand_temp,element4);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element6);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element8);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element13);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element14);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element15);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element16);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element17);

    strcpy(putKeyCommand,putKeyCommand_temp);

    return 1;
}

int tripleDES_ECB_encrypt(char *data, char *key, char *encrypted_data){

    if(strlen(data)!=16){
        //printf("\ntripleDES_ECB_encrypt() error : wrong data length !");
        printTime(vtime2);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ntripleDES_ECB_encrypt() error : wrong data length !\n",vtime2);
        fclose(flog);
        return 0;
    }

    unsigned char bytes_data_buf[8], bytes_encrypted_data_buf[8],
                  key1[8], key2[8];
    des_key_schedule ks1,ks2;

    //prepare key compenents
    stringToBytes(str_sub(key,0,15), key1);
    stringToBytes(str_sub(key,16,31), key2);
    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    //prepare data
    stringToBytes(data,bytes_data_buf);

    //encrypt
    des_ecb3_encrypt((DES_cblock *)bytes_data_buf, (DES_cblock *) bytes_encrypted_data_buf, ks1,ks2,ks1, DES_ENCRYPT);

    //the result
    bytesToString(bytes_encrypted_data_buf,8,encrypted_data);

    return 1;

}

int computeKCV(char *key, char *kcv){

    char buf[8*2+1]="", *kcv_temp;
    tripleDES_ECB_encrypt("0000000000000000",key,buf);
    kcv_temp = str_sub(buf,0,5);
    strncpy(kcv,kcv_temp,6);

    return 1;
}

void computeDiversifiedKey(char *key, char *s_diversifier, char *divKey){

    unsigned char bytes_diversifiedKey[16], diversifier[16];

    unsigned char key1[8], key2[8],iv[8];

    des_key_schedule ks1,ks2;

    char diversifiedKey[16*2+1]="";

    stringToBytes(s_diversifier,diversifier);
    stringToBytes(str_sub(key,0,15), key1);
    stringToBytes(str_sub(key,16,31), key2);

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(diversifier, bytes_diversifiedKey, (long) 16, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToString(bytes_diversifiedKey,16,diversifiedKey);

    strcpy(divKey,diversifiedKey);

}

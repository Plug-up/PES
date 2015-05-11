#include "pup_encryption_functions.h"

FILE *flog;
char var_time[30]="";

char ed_session_enc_key[16*2+1]="",
     ed_session_mac_key[16*2+1]="",
     ed_session_dek_key[16*2+1]="",
     ed_session_last_mac[8*2+1]="";

void asciiToHex(const char *s,char* s_hex){

    int i;
    char tmp[3]="";

    strcpy(s_hex,"");

    for(i=0;i<strlen(s);i++){
        sprintf(tmp,"%02hX",s[i]);
        strcat(s_hex,tmp);
    }
}

void hexToAscii(const char *s_hex,char* s){

    int i;
    char tmp[2]="";
    unsigned char b_s_hex[16];

    strcpy(s,"");
    stringToBytes(s_hex,b_s_hex);

    for(i=0;i<16;i++){
       sprintf(tmp,"%c",b_s_hex[i]);
       strcat(s,tmp);
    }

}

int createPlugUpAccess(hid_device *h, const char *password){

    char pass[255]="",
         gp_key[16*2+1]="",
         cmac0[8*2+1]="",
         cmac1[8*2+1]="",
         cmacKey[16*2+1] = "",
         sdekKey[16*2+1] = "",
         putKeycde[260*2+1]="",
         putKeycde_maced[260*2+1]="",
         data[255*2+1]="", sw[2*2+1]="";

    //Set password & generate a GP Key
    if(!createPassword(password,pass)){
        //printf("\ncreatePlugUpAccess() error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : cannot create password from user input !\n",var_time);
        fclose(flog);
        return 0;
    }
    if(!createGPKeyFromPass(pass,gp_key)){
        //printf("\ncreatePlugUpAccess() error : cannot generate GP key from password");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : cannot generate GP key from password\n",var_time);
        fclose(flog);
        return 0;
    }

    //retreive plug-up
    char sn_data[255*2+1]="", sn_sw[2*2+1]="",
         *diversifier;
    exchangeApdu(h,"80e6000012",sn_data,sn_sw);

    if(strcmp(sn_sw,"9000")){
        //printf("\ncreatePlugUpAccess() error : cannot retreive plug-up SN. exchangeApdu() returns %s !",sn_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : cannot retreive plug-up SN. exchangeApdu() returns %s !\n",var_time,sn_sw);
        fclose(flog);
        return 0;
    }
    else{
        diversifier = str_sub(sn_data,0,31);
    }
    char divKey[16*2+1]="";
    computeDiversifiedKey(KEYSET_01_GP_KEY,diversifier,divKey);

    //Try to open a secure channel to the selected plug-up using keyset "01"
    if(!openSecureChannel(h,"01",divKey,cmacKey,cmac0,sdekKey)){
        //printf("\ncreatePlugUpAccess() error : Can not open SC \"01\" !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : Can not open SC \"01\" !\n",var_time);
        fclose(flog);
        return 0;
    }

    //put key, create keyset PASS_KEYSET_VERSION
    if(!createPutKeyCommand(PASS_KEYSET_VERSION,"81",sdekKey,gp_key,gp_key,gp_key,"81","0001",putKeycde)){
        //printf("\ncreatePlugUpAccess() error : createPutKeyCommand() error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : createPutKeyCommand() error !\n",var_time);
        fclose(flog);
        return 0;
    }

    macedCommand(putKeycde,cmacKey,cmac0,cmac1,putKeycde_maced); //mac the putkey command

    //exchange putkey command
    exchangeApdu(h,putKeycde_maced,data,sw);
    if(strcmp(sw,"9000")){
        //printf("\ncreatePlugUpAccess() error : exchangeApdu() returns %s",sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreatePlugUpAccess() error : exchangeApdu() returns %s\n",var_time,sw);
        fclose(flog);
        return 0;
    }

    //close sc : any apdu without security
    char any_data[255*2+1]="", any_sw[2*2+1]="";
    exchangeApdu(h,"80e6000012",any_data,any_sw);

    //end
    //printf("\ncreatePlugUpAccess() success!");
    return 1;
}

int createEncryptionMasterKey(hid_device *h, char *encMasterKey){

        //generate 16-byte key. Append 16(ff) to make macedCommand() compatible with APDUs with Le
        char genRandom[260*2+1]="d024000010ffffffffffffffffffffffffffffffff",
             genRandom_mac[8*2+1]="",
             genRandom_maced[260*2+1]="",
             genRandom_data[250*2+1]="",
             genRandom_sw[2*2+1]="";

        //mac the command genRandom
        macedCommand(genRandom, ed_session_mac_key, ed_session_last_mac, genRandom_mac, genRandom_maced);

        //exchange
        exchangeApdu(h,genRandom_maced,genRandom_data,genRandom_sw);

        if(strcmp(genRandom_sw,"9000")){
            //printf("\ncreateEncryptionMasterKey() error : cannot generate key. exchangeApdu() returns sw %s",genRandom_sw);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\ncreateEncryptionMasterKey() error : cannot generate key. exchangeApdu() returns sw %s\n",var_time,genRandom_sw);
            fclose(flog);
            return 0;
        }
        else{
            strcpy(ed_session_last_mac, genRandom_mac);
        }

    //create a plug-up encryption/decryption key with value set to the generated 16-bytes
    char putKeycde_mac[8*2+1]="",
         putKeycde[260*2+1]="",
         putKeycde_maced[260*2+1]="",
         putKey_data[255*2+1]="", putKey_sw[2*2+1]="";

    //put key, create keyset ENC_KEYSET_VERSION encrypt/decrypt key
    if(!createPutKeyCommand(ENC_KEYSET_VERSION,"81",ed_session_dek_key,genRandom_data,genRandom_data,genRandom_data,"08","AFAF",putKeycde)){
        //printf("\ncreateEncryptionMasterKey() error : createPutKeyCommand() error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreateEncryptionMasterKey() error : createPutKeyCommand() error !\n",var_time);
        fclose(flog);
        return 0;
    }

    macedCommand(putKeycde,ed_session_mac_key,ed_session_last_mac,putKeycde_mac,putKeycde_maced); //mac the putkey command

    //exchange
    exchangeApdu(h,putKeycde_maced,putKey_data,putKey_sw);
    if(strcmp(putKey_sw,"9000")){
        //printf("\ncreateEncryptionMasterKey() error : cannot write key to plug-up. exchangeApdu()returns %s",putKey_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreateEncryptionMasterKey() error : cannot write key to plug-up. exchangeApdu()returns %s\n",var_time,putKey_sw);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac,putKeycde_mac);
    }

    //end
    //printf("\ncreateEncryptionMasterKey() success!");
    printTime(var_time);
    flog = fopen(LOG_FILE_NAME,"a");
    fprintf(flog,"%s\ncreateEncryptionMasterKey() success!\n",var_time);
    fclose(flog);
    strcpy(encMasterKey,genRandom_data);
    return 1;

}

int generatePassword(char *password){

    char min[26] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'},
         maj[26] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'},
         num[10] = {'0','1','2','3','4','5','6','7','8','9'},
         spec[27] = {'~','!','@','#','$','%','^','&','*','(',')','-','_','=','+','[',']','{','}',';',':',',','.','<','>','/','?'},
         mdp[16+1]="";

    int i = 0, ch1=0, ch2=0, nmin = 0, nmaj = 0, nnum = 0 , nspec = 0;

    srand(time(NULL));

    while(i<16){
        ch1 = rand()%(4-0)+0;
        if((ch1==0)&&(nmin<4)){
            ch2 = rand()%(26-0)+0;
            mdp[i] = min[ch2];
            nmin++;
            i++;
        }
        else if((ch1==1)&&(nmaj<4)){
            ch2 = rand()%(26-0)+0;
            mdp[i] = maj[ch2];
            nmaj++;
            i++;
        }
        else if((ch1==2)&&(nnum<4)){
            ch2 = rand()%(10-0)+0;
            mdp[i] = num[ch2];
            nnum++;
            i++;
        }
        else if((ch1==3)&&(nspec<4)){
            ch2 = rand()%(27-0)+0;
            mdp[i] = spec[ch2];
            nspec++;
            i++;
        }
    }

    mdp[16]='\0';

    strcpy(password,mdp);

    return 1;
}

int createPassword(const char *input, char *password){

    char gPass[16+1]="";

    if(!strcmp(input,"")){
        //printf("\nA strong 16-character password is generated randomly!");
        if(generatePassword(gPass)){
            strcpy(password,gPass);
        }
        else{
            //printf("\ncreatePassword() error !");
            return 0;
        }
    }
    else {
        strcpy(password,input);
    }

    return 1;

}

int createGPKeyFromPass(const char *password, char *gpKey){

    unsigned char pass_bytes[255], digest[20];
    char pass_hex[255*2+1]="", digest_string[20*2+1]="";

    asciiToHex(password,pass_hex); //ascii to hex representation
    stringToBytes(pass_hex,pass_bytes); //to unsigned char array

    if(SHA1(pass_bytes, strlen(password), digest)==NULL){ //sha1 digest, 160 bit = 20 bytes
        //printf("\ncreateGPKeyFromPass() error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreateGPKeyFromPass() error !\n",var_time);
        fclose(flog);
        return 0;
    }

    bytesToString(digest,20,digest_string);
    strcpy(gpKey,str_sub(digest_string,0,31)); //16 first bytes (gp key len)

    return 1;

}

int fileEncryption(hid_device *h, const char *fileName, char *keyVersion, int encDec){

    char iv_key[255*2+1]="", iv_file[255*2+1]="", fileId[255*2+1]="";

    if(encDec){ //encryption case : generate random IV & FILE_ID

        char genRandomIV_key[260*2+1]="d024000008ffffffffffffffff",
             genRandomIV_file[260*2+1]="d024000010ffffffffffffffffffffffffffffffff",
             genRandomID[260*2+1]="d024000010ffffffffffffffffffffffffffffffff",
             genRandom_mac[8*2+1]="",
             genRandom_maced[260*2+1]="",
             genRandom_sw[2*2+1]="";

        //mac the command genRandomIV_key
        macedCommand(genRandomIV_key, ed_session_mac_key, ed_session_last_mac, genRandom_mac, genRandom_maced);

        //exchange
        exchangeApdu(h,genRandom_maced,iv_key,genRandom_sw);

        if(strcmp(genRandom_sw,"9000")){
            //printf("\nfileEncryption() error : cannot generate key IV. exchangeApdu() returns sw %s",genRandom_sw);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() error : cannot generate key IV. exchangeApdu() returns sw %s\n",var_time,genRandom_sw);
            fclose(flog);
            return 0;
        }
        strcpy(ed_session_last_mac, genRandom_mac);

        //mac the command genRandomIV_file
        macedCommand(genRandomIV_file, ed_session_mac_key, ed_session_last_mac, genRandom_mac, genRandom_maced);

        //exchange
        exchangeApdu(h,genRandom_maced,iv_file,genRandom_sw);

        if(strcmp(genRandom_sw,"9000")){
            //printf("\nfileEncryption() error : cannot generate file IV. exchangeApdu() returns sw %s",genRandom_sw);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() error : cannot generate file IV. exchangeApdu() returns sw %s\n",var_time,genRandom_sw);
            fclose(flog);
            return 0;
        }
        strcpy(ed_session_last_mac, genRandom_mac);

        //mac the command genRandomID
        macedCommand(genRandomID, ed_session_mac_key, ed_session_last_mac, genRandom_mac, genRandom_maced);

        //exchange
        exchangeApdu(h,genRandom_maced,fileId,genRandom_sw);

        if(strcmp(genRandom_sw,"9000")){
            //printf("\nfileEncryption() error : cannot generate file ID. exchangeApdu() returns sw %s",genRandom_sw);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() error : cannot generate file ID. exchangeApdu() returns sw %s\n",var_time,genRandom_sw);
            fclose(flog);
            return 0;
        }
        strcpy(ed_session_last_mac, genRandom_mac);

    }
    else{ //decryption case : retreive IV_key, IV_file & FILE_ID from the encrypted file
        char iv_fileid_s[40*2+1]="", *iv_key_s, *iv_file_s, *fileid_s;
        unsigned char iv_fileid[40];

        FILE *f = fopen(fileName,"rb");
        if(f==NULL){
            //printf("\nfileEncryption() : Opening encrypted file error. The file %s may not exist !",fileName);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() : Opening encrypted file error. The file %s may not exist !\n",var_time,fileName);
            fclose(flog);
            return 0;
        }
        int len = fread(iv_fileid, 1, 40, f);
        fclose(f);
        if(len != 40){
            //printf("\nfileEncryption() : Retreiving file ID error !");
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() : Retreiving file ID error !\n",var_time);
            fclose(flog);
            return 0;
        }
        bytesToString(iv_fileid,40,iv_fileid_s);
        iv_key_s = str_sub(iv_fileid_s,0,15);
        iv_file_s = str_sub(iv_fileid_s,16,47);
        fileid_s = str_sub(iv_fileid_s,48,79);
        strcpy(iv_file,iv_file_s);
        strcpy(iv_key,iv_key_s);
        strcpy(fileId,fileid_s);
    }

    //create file encryption key
    char fileEncryptionKey[16*2+1]="";
    if(!createFileEncryptionKey(h,keyVersion,iv_key,fileId,fileEncryptionKey)){
        //printf("\nfileEncryption() : creating file encryption key error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nfileEncryption() : creating file encryption key error !\n",var_time);
        fclose(flog);
        return 0;
    }

    //encrypt/decrypt
    if(!do_crypt(fileName,fileEncryptionKey,iv_key,iv_file,fileId,encDec)){
        if(encDec){
            //printf("\nfileEncryption() : file encryption error !");
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() : file encryption error !\n",var_time);
            fclose(flog);
        }
        else{
            //printf("\nfileEncryption() : file decryption error !");
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nfileEncryption() : file decryption error !\n",var_time);
            fclose(flog);
        }
        return 0;
    }

    return 1;

}

int openSC_UsingPass(hid_device *h, char *keyset, const char *pass){

    //get the master GP Key
    char gpKey[16*2+1]="";
    createGPKeyFromPass(pass,gpKey);

    //get a diversified key : first, get plug-up serial number to use its 16-first-bytes as diversifier
    char *diversifier,
         data[255*2+1]="", sw[2*2+1]="";

    exchangeApdu(h, "80e6000012",data,sw);
    if(!strcmp(sw,"9000")){
        diversifier=str_sub(data,0,31);
    }
    else{
        return 0;
    }
    //then, diversify
    char divKey[16*2+1]="";
    computeDiversifiedKey(gpKey,diversifier,divKey);

    //try to open the sc
    if(!openSecureChannel(h,keyset,divKey,ed_session_mac_key,ed_session_last_mac,ed_session_dek_key)){
        //printf("\nopenSC_UsingPass() error ! Can not open the SC !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nopenSC_UsingPass() error ! Can not open the SC !\n",var_time);
        fclose(flog);
        return 0;
    }
    else{
        return 1;
    }


}

int createFileEncryptionKey(hid_device *h, char *masterKeyVersion, char *iv, char *fileID, char *fileEncryptionKey){

    //create "encrypt" command with cbc mode
    char encryptCde[260*2+1] = "d02001021a",
         encryptCde_mac[8*2+1]="",
         encryptCde_maced[260*2+1]="",
         encryptCde_data[255*2+1]="", encryptCde_sw[2*2+1]="";

    strcat(encryptCde,masterKeyVersion);
    strcat(encryptCde,"01");
    strcat(encryptCde,iv);
    strcat(encryptCde,fileID);

    //mac the command
    macedCommand(encryptCde, ed_session_mac_key, ed_session_last_mac, encryptCde_mac, encryptCde_maced);

    //exchange
    exchangeApdu(h,encryptCde_maced,encryptCde_data,encryptCde_sw);

    if(strcmp(encryptCde_sw,"9000")){
        //printf("\ncreateFileEncryptionKey() error : exchangeApdu() returns sw %s",encryptCde_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ncreateFileEncryptionKey() error : exchangeApdu() returns sw %s\n",var_time,encryptCde_sw);
        fclose(flog);
        return 0;
    }
    strcpy(ed_session_last_mac, encryptCde_mac);
    strcpy(fileEncryptionKey,encryptCde_data);

    return 1;
}

int do_crypt (const char *infile, const char *key_s, const char *iv_key_s, const char *iv_file_s, const char *fileId_s, int do_encrypt){

    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[SIZE_BUF], outbuf[SIZE_BUF + EVP_MAX_BLOCK_LENGTH],
                  key[16], iv[16];

    char outfile[255]="";

    int inlen = 0, outlen = 0;

    FILE *in = fopen(infile,"rb"),
         *out;

    if(in==NULL) {
        //printf("\ndo_crypt error : file %s not found !",infile);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndo_crypt error : file %s not found !\n",var_time,infile);
        fclose(flog);
        return 0;
    }

    if(do_encrypt){ //if encryption case
        char iv_fileid_s[40*2+1]="";
        unsigned char iv_fileid[40];
        strcat(iv_fileid_s,iv_key_s);
        strcat(iv_fileid_s,iv_file_s);
        strcat(iv_fileid_s,fileId_s);
        stringToBytes(iv_fileid_s,iv_fileid);
        strcat(outfile,infile);
        strcat(outfile,".pes");
        out = fopen(outfile,"wb");
        if(out==NULL) {
            fclose(in);
            //printf("\ndo_crypt() : an error occured when writing to the file %s !",outfile);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\ndo_crypt() : an error occured when writing to the file %s !\n",var_time,outfile);
            fclose(flog);
            return 0;
        }
        fwrite(iv_fileid, 1, 40, out);
    }
    else{ //if decryption case
        strncpy(outfile,infile,strlen(infile)-4);
        out = fopen(outfile,"wb");
        if(out==NULL) {
            fclose(in);
            //printf("\ndo_crypt() : an error occured when writing to the file %s !",outfile);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\ndo_crypt() : an error occured when writing to the file %s !\n",var_time,outfile);
            fclose(flog);
            return 0;
        }
        inlen = fread(inbuf, 1, 40, in); //Read IVs+FILE_ID = header (to pass directly to encrypted data)
    }

    stringToBytes(key_s,key);
    stringToBytes(iv_file_s,iv);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);
    for(;;)
    {
        inlen = fread(inbuf, 1, SIZE_BUF, in);
        if(inlen <= 0) break;
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            fclose(in);
            fclose(out);
            remove(outfile);
            //printf("\ndo_crypt() Error : in EVP_CipherUpdate()");
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\ndo_crypt() Error : in EVP_CipherUpdate()\n",var_time);
            fclose(flog);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
    {
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        fclose(in);
        fclose(out);
        remove(outfile);
        //printf("\ndo_crypt() Error : in EVP_CipherFinal_ex()");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndo_crypt() Error : in EVP_CipherFinal_ex()\n",var_time);
        fclose(flog);
        return 0;
    }

    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(&ctx);

    fclose(in);
    fclose(out);

    remove(infile);

    return 1;
}

int deleteKeyset(hid_device *h, char *keysetVersion){

    /*Select keyset file*/
    char select1[260*2+1]="80a4000002", select2[260*2+1]="80a4000002", select3[260*2+1]="80a4000002", select4[260*2+1]="80a4000002",
         select5[260*2+1]="80a4000002", select_maced[260*2+1]="", select_mac[8*2+1]="",
         select_data[255*2+1]="", select_sw[2*2+1]="";

    strcat(select1,"3f00");
    strcat(select2,"c00f");
    strcat(select3,"c0de");
    strcat(select4,"0001");
    strcat(select5,"10");
    strcat(select5,keysetVersion);

    macedCommand(select1,ed_session_mac_key,ed_session_last_mac,select_mac,select_maced);
    exchangeApdu(h,select_maced,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot select MF. exchangeApdu() returns sw %s\n%s",select_sw,select_data);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot select MF. exchangeApdu() returns sw %s\n%s\n",var_time,select_sw,select_data);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, select_mac);
    }

    macedCommand(select2,ed_session_mac_key,ed_session_last_mac,select_mac,select_maced);
    exchangeApdu(h,select_maced,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot select EF C00F. exchangeApdu() returns sw %s\n%s",select_sw,select_data);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot select EF C00F. exchangeApdu() returns sw %s\n%s\n",var_time,select_sw,select_data);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, select_mac);
    }

    macedCommand(select3,ed_session_mac_key,ed_session_last_mac,select_mac,select_maced);
    exchangeApdu(h,select_maced,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot select EF C0DE. exchangeApdu() returns sw %s",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot select EF C0DE. exchangeApdu() returns sw %s\n",var_time,select_sw);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, select_mac);
    }

    macedCommand(select4,ed_session_mac_key,ed_session_last_mac,select_mac,select_maced);
    exchangeApdu(h,select_maced,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot select EF 0001. exchangeApdu() returns sw %s",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot select EF 0001. exchangeApdu() returns sw %s\n",var_time,select_sw);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, select_mac);
    }

    macedCommand(select5,ed_session_mac_key,ed_session_last_mac,select_mac,select_maced);
    exchangeApdu(h,select_maced,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot select 10%s. exchangeApdu() returns sw %s",keysetVersion,select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot select 10%s. exchangeApdu() returns sw %s\n",var_time,keysetVersion,select_sw);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, select_mac);
    }
    /*end select*/


    /*delete keyset file*/
    char deleteKF[260*2+1]="80e4000002", deleteKF_maced[260*2+1]="", deleteKF_mac[8*2+1]="",
         deleteKF_data[255*2+1]="", deleteKF_sw[2*2+1]="";

    strcat(deleteKF,"10");
    strcat(deleteKF,keysetVersion);

    macedCommand(deleteKF,ed_session_mac_key,ed_session_last_mac,deleteKF_mac,deleteKF_maced);
    exchangeApdu(h,deleteKF_maced,deleteKF_data,deleteKF_sw);
    if(strcmp(deleteKF_sw,"9000")){
        //printf("\ndeleteKeyset() error : cannot delete EF 10%s. exchangeApdu() returns sw %s",keysetVersion,deleteKF_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\ndeleteKeyset() error : cannot delete EF 10%s. exchangeApdu() returns sw %s\n",var_time,keysetVersion,deleteKF_sw);
        fclose(flog);
        return 0;
    }
    else{
        strcpy(ed_session_last_mac, deleteKF_mac);
    }
    /*end delete*/

    //printf("\ndeleteKeyset() success !");
    printTime(var_time);
    flog = fopen(LOG_FILE_NAME,"a");
    fprintf(flog,"%s\ndeleteKeyset() success !\n",var_time);
    fclose(flog);
    return 1;
}

int isAnEncryptionPup(hid_device *h, char *encryptionKeysetVersion){

    char select1[260*2+1]="80a4000002",select2[260*2+1]="80a4000002", select3[260*2+1]="80a4000002", select4[260*2+1]="80a4000002",
         select5[260*2+1]="80a4000002",
         select_data[255*2+1]="", select_sw[2*2+1]="";

    strcat(select1,"3f00");
    strcat(select2,"c00f");
    strcat(select3,"c0de");
    strcat(select4,"0001");
    strcat(select5,"10");
    strcat(select5,encryptionKeysetVersion);

    exchangeApdu(h,select1,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\nisAnEncryptionPup() error : cannot select MF. exchangeApdu() returns sw %s\nRemove plug-up, reinsert it then retry !",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nisAnEncryptionPup() error : cannot select MF. exchangeApdu() returns sw %s\nRemove plug-up, reinsert it then retry !\n",var_time,select_sw);
        fclose(flog);
        return 2;
    }

    exchangeApdu(h,select2,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\nisAnEncryptionPup() error : cannot select EF C00F. exchangeApdu() returns sw %s\nRemove plug-up, reinsert it then retry !",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nisAnEncryptionPup() error : cannot select EF C00F. exchangeApdu() returns sw %s\nRemove plug-up, reinsert it then retry !\n",var_time,select_sw);
        fclose(flog);
        return 2;
    }

    exchangeApdu(h,select3,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\nisAnEncryptionPup() error : cannot select EF C0DE. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nisAnEncryptionPup() error : cannot select EF C0DE. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !\n",var_time,select_sw);
        fclose(flog);
        return 2;
    }

    exchangeApdu(h,select4,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        //printf("\nisAnEncryptionPup() error : cannot select EF 0001. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !",select_sw);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nisAnEncryptionPup() error : cannot select EF 0001. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !\n",var_time,select_sw);
        fclose(flog);
        return 2;
    }

    exchangeApdu(h,select5,select_data,select_sw);
    if(strcmp(select_sw,"9000")){
        if(strcmp(select_sw,"9404")){
            //printf("\nisAnEncryptionPup() error : cannot select EF 10%s. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !",encryptionKeysetVersion,select_sw);
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nisAnEncryptionPup() error : cannot select EF 10%s. exchangeApdu() returns sw %sRemove plug-up, reinsert it then retry !\n",var_time,encryptionKeysetVersion,select_sw);
            fclose(flog);
            return 2;
        }
        else{
            //printf("\nisAnEncryptionPup() error : encryption keyset does not exist !");
            printTime(var_time);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nisAnEncryptionPup() error : encryption keyset does not exist !\n",var_time);
            fclose(flog);
            return 0;
        }
    }

    return 1;
}

int retreiveFileEncryptionKeyFromEncryptedFile(hid_device *h, const char *fileName, char *keyVersion, char *fileEncryptionKey){

    char iv_key[255*2+1]="", iv_file[255*2+1]="", fileId[255*2+1]="";
    char iv_fileid_s[40*2+1]="", *iv_key_s, *iv_file_s, *fileid_s;
    unsigned char iv_fileid[40];

    FILE *f = fopen(fileName,"rb");
    if(f==NULL){
        //printf("\nretreiveFileEncryptionKeyFromEncryptedFile() : Opening encrypted file error. The file %s may not exist !",fileName);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nretreiveFileEncryptionKeyFromEncryptedFile() : Opening encrypted file error. The file %s may not exist !\n",var_time,fileName);
        fclose(flog);
        return 0;
    }
    int len = fread(iv_fileid, 1, 40, f);
    fclose(f);
    if(len != 40){
        //printf("\nretreiveFileEncryptionKeyFromEncryptedFile() : Retreiving file ID error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nretreiveFileEncryptionKeyFromEncryptedFile() : Retreiving file ID error !\n",var_time);
        fclose(flog);
        return 0;
    }
    bytesToString(iv_fileid,40,iv_fileid_s);
    iv_key_s = str_sub(iv_fileid_s,0,15);
    iv_file_s = str_sub(iv_fileid_s,16,47);
    fileid_s = str_sub(iv_fileid_s,48,79);
    strcpy(iv_file,iv_file_s);
    strcpy(iv_key,iv_key_s);
    strcpy(fileId,fileid_s);

    //create file encryption key
    if(!createFileEncryptionKey(h,keyVersion,iv_key,fileId,fileEncryptionKey)){
        //printf("\nretreiveFileEncryptionKeyFromEncryptedFile() : creating file encryption key error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nretreiveFileEncryptionKeyFromEncryptedFile() : creating file encryption key error !\n",var_time);
        fclose(flog);
        return 0;
    }

    return 1;
}

int fileDecryptionUsingPassKey(char *fileName, char *fileDecryptionKey){

    char iv_key[255*2+1]="", iv_file[255*2+1]="", fileId[255*2+1]="";
    char iv_fileid_s[40*2+1]="", *iv_key_s, *iv_file_s, *fileid_s;
    unsigned char iv_fileid[40];

    FILE *f = fopen(fileName,"rb");
    if(f==NULL){
        //printf("\nfileDecryptionUsingPassKey() : Opening encrypted file error. The file %s may not exist !",fileName);
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nfileDecryptionUsingPassKey() : Opening encrypted file error. The file %s may not exist !\n",var_time,fileName);
        fclose(flog);
        return 0;
    }
    int len = fread(iv_fileid, 1, 40, f);
    fclose(f);
    if(len != 40){
        //printf("\nfileDecryptionUsingPassKey() : Retreiving file ID error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nfileDecryptionUsingPassKey() : Retreiving file ID error !\n",var_time);
        fclose(flog);
        return 0;
    }

    bytesToString(iv_fileid,40,iv_fileid_s);
    iv_key_s = str_sub(iv_fileid_s,0,15);
    iv_file_s = str_sub(iv_fileid_s,16,47);
    fileid_s = str_sub(iv_fileid_s,48,79);
    strcpy(iv_file,iv_file_s);
    strcpy(iv_key,iv_key_s);
    strcpy(fileId,fileid_s);

    //decrypt
    if(!do_crypt(fileName,fileDecryptionKey,iv_key,iv_file,fileId,0)){
        //printf("\nfileDecryptionUsingPassKey()() : file decryption error !");
        printTime(var_time);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nfileDecryptionUsingPassKey()() : file decryption error !\n",var_time);
        fclose(flog);
        return 0;
    }

    return 1;
}


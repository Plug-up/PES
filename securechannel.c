/*
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/
#include "securechannel.h"

//for log
FILE *flog;
char vtime[30]="";
//

int openSecureChannel(hid_device *plug_up,char* keysetId, char *div_key, char* c_macKey, char* c_mac, char *s_dekKey){

    int retvalue=0,
        ccc;
    char s_hostChallenge[8*2+1] = "",
         d_initializeUpdateApdu[SIZE_BYTES_APDU*2+1] = "",
         externalAuthenticateApdu[SIZE_BYTES_APDU*2+1]= "",
         s_init_up_data[SIZE_BYTES_APDU_REP_DATA*2+1]="",
         computedCardCryptogram[8*2+1]="",
         s_encKey[16*2+1] = "",
         //c_macKey[16*2+1] = "",
         tmp_diversifier[18*2+1]="",
         hostCryptogram[8*2+1] = "",
         //c_mac[8*2+1] = "",
         externalAuthenticateApdu_mac[SIZE_BYTES_APDU*2+1]="",
         *counter = "",
         *cardChallenge = "",
         *returnedCardCryptogram = "",
         *diversifier="",
         sw[2*2+1]="",
         s_ext_auth_data[SIZE_BYTES_APDU_REP_DATA*2+1]="";

    unsigned char hostChallenge[8];


    //generate host challenge
    generateChallenge(hostChallenge,8);
    bytesToString(hostChallenge,8,s_hostChallenge);

    //get plug-up serial number to use its 16-first-bytes as diversifier
    exchangeApdu(plug_up, "80e6000012",tmp_diversifier,sw);
    if(!strcmp(sw,"9000")){
        diversifier=str_sub(tmp_diversifier,0,31);
    }
    else{
        //printf("\nopenSecureChannel() error : can not retreive plug-up SN. exchangeApdu() returned %s",sw);
        printTime(vtime);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nopenSecureChannel() error : can not retreive plug-up SN. exchangeApdu() returned %s\n",vtime,sw);
        fclose(flog);
        return retvalue;
    }

    //diversified initialize update creation & sending
    diversifiedInitializeUpdate(keysetId, s_hostChallenge,diversifier, d_initializeUpdateApdu);
    exchangeApdu(plug_up, d_initializeUpdateApdu,s_init_up_data,sw);

    //get data from initialize update response
    if(!strcmp(sw,"9000")){

        counter = str_sub(s_init_up_data, 24, 27);
        cardChallenge = str_sub(s_init_up_data, 28, 39);
        returnedCardCryptogram = str_sub(s_init_up_data, 40, 56);
    }
    else{
    //log - output sw meaning
        //printf("\nopenSecureChannel() error : initialize update returned %s",sw);
        printTime(vtime);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nopenSecureChannel() error : initialize update returned %s\n",vtime,sw);
        fclose(flog);
        //exit(EXIT_FAILURE);
        return retvalue;
    }

    //compute session dek key and return it in parameters. In case of need it will be used. (to form "put key" command for example)
    computeSessionKey(counter,"0181", div_key, s_dekKey);

    //compute session enc key
    computeSessionKey(counter,"0182",div_key,s_encKey);

    //compute card cryptogram
    computeCardCryptogram(s_hostChallenge,cardChallenge,counter,s_encKey,computedCardCryptogram);

    //check card cryptogram
    ccc = checkCardCryptogram(returnedCardCryptogram,computedCardCryptogram);
    if(ccc!=SUCCESS){
        //printf("\nopenSecureChannel() error : Card Cryptogram verification failed !");
        printTime(vtime);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nopenSecureChannel() error : Card Cryptogram verification failed !\n",vtime);
        fclose(flog);
        //exit(EXIT_FAILURE);
        return retvalue;
    }
    else{
        //compute data that an external authenticate apdu needs

        computeHostCryptogram(s_hostChallenge, cardChallenge, counter, s_encKey, hostCryptogram);
        computeSessionKey(counter, "0101", div_key, c_macKey);
        externalAuthenticate(SECURITY_LEVEL, hostCryptogram,externalAuthenticateApdu);
        macedCommand(externalAuthenticateApdu,c_macKey,"",c_mac,externalAuthenticateApdu_mac);

        //send external authenticate
        exchangeApdu(plug_up, externalAuthenticateApdu_mac, s_ext_auth_data, sw);

        //get data from external authenticate response
        if(!strcmp(sw,"9000")){
            //printf("\nopenSecureChannel() success : SC opened !");
            printTime(vtime);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nopenSecureChannel() success : SC opened !\n",vtime);
            fclose(flog);
            retvalue=1;
        }
        else{
        //output sw meaning
            //printf("\nopenSecureChannel() : external authenticate returned %s",sw);
            printTime(vtime);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nopenSecureChannel() : external authenticate returned %s\n",vtime,sw);
            fclose(flog);
            //exit(EXIT_FAILURE);
            return retvalue;
        }
    }

    return retvalue;
}

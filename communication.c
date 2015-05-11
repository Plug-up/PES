/**
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/

#include "communication.h"
#include "common.h"

FILE *flog;
char vtime3[30]="";

void exchangeApdu(hid_device *h,const char *input,char *s_data, char* s_sw){

    //FILE *f = fopen("HID_report_log.txt","a"); //HID Reports LOG

    int i=0,j=0,k=0,tdu=0,nbl=0,t_input=0,t_data=0,nbr=0,nbw=0,pad=0,isHexa=0,t_apdu=0;

    unsigned char apdu_cde[SIZE_BYTES_APDU],apdu_rep[T_BLOC * 5],//apdu command, apdu response (All read blocs, its size is 5 * 64 at max)
                  w_bloc[T_BLOC+1],//bloc to write
                  r_bloc[T_BLOC];//bloc to read

    unsigned char data[SIZE_BYTES_APDU_REP_DATA], sw[2];


    t_input = strlen(input); //user input size

    //is the command in hex format?
    isHexa=1;
    for(i=0;i<t_input;i++)
    {
        if(input[i]!='0'&&input[i]!='1'&&input[i]!='2'&&input[i]!='3'&&input[i]!='4'&&
           input[i]!='5'&&input[i]!='6' &&input[i]!='7'&&input[i]!='8'&&input[i]!='9'&&
           input[i]!='a'&&input[i]!='b'&&input[i]!='c'&&input[i]!='d'&&input[i]!='e'&&input[i]!='f'&&
           input[i]!='A'&&input[i]!='B'&&input[i]!='C'&&input[i]!='D'&&input[i]!='E'&&input[i]!='F')

            {isHexa = 0; break;}

    }

    if(t_input%2 != 0 || t_input==0 || !isHexa){ //invalid command
        //printf("Error : wrong apdu !\n");
        printTime(vtime3);
        flog = fopen(LOG_FILE_NAME,"a");
        fprintf(flog,"%s\nexchangeApdu() Error : wrong apdu !\n",vtime3);
        fclose(flog);
        return;
    }
    else{//form the apdu

        t_apdu = t_input/2; //apdu size in bytes

        stringToBytes(input,apdu_cde);

        //decompose the apdu to blocs of T_BLOC bytes
        i=0;
        w_bloc[0]=0x00;//fake report number

        while(i+T_BLOC < t_apdu)
        {
            for(j=1;j<T_BLOC+1;j++){
                w_bloc[j]=apdu_cde[i+j-1];
            }

            /*print written reports to log file
            char b[(T_BLOC+1)*2+1]="";
            bytesToString(w_bloc,T_BLOC+1,b);
            fprintf(f,"write bloc:\n%s\n",b);
            //*/

            //write bloc to plug-up
            nbw = hid_write(h,w_bloc,T_BLOC+1);
            if (nbw < 0) {
                //printf("Write apdu failure !\n");
                //printf("Error: %ls\n", hid_error(h));
                printTime(vtime3);
                flog = fopen(LOG_FILE_NAME,"a");
                fprintf(flog,"%s\nexchangeApdu() Error : Write apdu failure !\n",vtime3);
                fclose(flog);
                return;
            }

            i=i+T_BLOC; //next bloc
        }

        //Pad last bloc with 0x00
        pad = i+T_BLOC+1-t_apdu;
        for(j=1;j<T_BLOC+1;j++){
            if(j<T_BLOC+1-pad+1){
                w_bloc[j]=apdu_cde[i+j-1];
            }
            else{
                w_bloc[j]=0x00;
            }
        }

        /*log
        char b[(T_BLOC+1)*2+1]="";
        bytesToString(w_bloc,T_BLOC+1,b);
        fprintf(f,"write bloc:\n%s\n",b);
        //*/

        //Write last bloc
        nbw = hid_write(h,w_bloc,T_BLOC+1);
        if (nbw < 0) {
            //printf("Echec write !\n");
            //printf("Error: %ls\n", hid_error(h));
            printTime(vtime3);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nexchangeApdu() Error : Write apdu failure !\n",vtime3);
            fclose(flog);
            return;
        }
    }

    //read the apdu response

    nbr = hid_read(h,r_bloc,T_BLOC); //read first bloc
        if (nbr < 0) {
            //printf("Read failure !\n");
            //printf("Error: %ls\n", hid_error(h));
            printTime(vtime3);
            flog = fopen(LOG_FILE_NAME,"a");
            fprintf(flog,"%s\nexchangeApdu() Error : read failure !\n",vtime3);
            fclose(flog);
            return;
        }

        /*log
        char b1[T_BLOC*2+1]="";
        bytesToString(r_bloc,T_BLOC,b1);
        fprintf(f,"read bloc:\n%s\n",b1);
        //*/

        if(r_bloc[0]!=0x61){ //response without data
            //printf("Response without data..\n");
            sw[0]=r_bloc[0];
            sw[1]=r_bloc[1];
            strcpy(s_data,"");
        }

        else{ //response with data
            //printf("\nresponse with data..\n");
            t_data=r_bloc[1];
            tdu=t_data+4;//read data without padding = 2 first bytes+data+sw1+sw2
            if(tdu%T_BLOC==0) nbl=tdu/T_BLOC; else nbl=(tdu/T_BLOC)+1; //reads number = blocs number

            j=0;
            for(i=0;i<T_BLOC;i++,j++){
                apdu_rep[j]=r_bloc[i];
            }

            //reading bloc by bloc
            for(k=0;k<nbl-1;k++){
                    nbr = hid_read(h,r_bloc,T_BLOC);
                    if (nbr < 0) {
                        //printf("\nread failure");
                        //printf("\nError: %ls", hid_error(h));
                        printTime(vtime3);
                        flog = fopen(LOG_FILE_NAME,"a");
                        fprintf(flog,"%s\nexchangeApdu() Error : read failure !\n",vtime3);
                        fclose(flog);
                        return;
                    }

                    /*log
                    char b1[T_BLOC*2+1]="";
                    bytesToString(r_bloc,T_BLOC,b1);
                    fprintf(f,"Read bloc:\n%s\n",b1);
                    //*/

                    for(i=0;i<T_BLOC;i++,j++){
                        apdu_rep[j]=r_bloc[i];
                    }
            }

            //Extract data
            for(i=2;i<t_data+2;i++){
                data[i-2]=apdu_rep[i];
            }


            //Extract status word
            for(i=t_data+2;i<tdu;i++){
                sw[i-t_data-2]=apdu_rep[i];
            }

        bytesToString(data,t_data,s_data);

        }

        bytesToString(sw,2,s_sw);


        //fclose(f);

}

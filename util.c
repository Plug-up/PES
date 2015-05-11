#include "util.h"

char *str_sub (const char *s, unsigned int start, unsigned int end)
{
   char *new_s = NULL;

   if (s != NULL && start < end)
   {

      new_s = malloc (sizeof (*new_s) * (end - start + 2));
      if (new_s != NULL)
      {
         int i;
         for (i = start; i <= end; i++)
         {
            new_s[i-start] = s[i];
         }
         new_s[i-start] = '\0';
      }
      else
      {
         fprintf (stderr, "Memoire insuffisante\n");
         exit (EXIT_FAILURE);
      }
   }
   return new_s;
}

void bytesToString(unsigned char *bytes,int t_bytes,char *string){

    int i;
    char tmp[3]="";
    strcpy(string,"");

    for(i=0;i<t_bytes;i++){
        sprintf(tmp,"%02hx",bytes[i]);
        strcat(string,tmp);
    }

}

void stringToBytes(const char *string, unsigned char *bytes){

    int i,j,tmp, t_string;
    char *byte;

    t_string=strlen(string);

    for(i=0,j=0;i<t_string-1;i=i+2,j++){
        byte=str_sub(string,i,i+1); //extract bytes
        sscanf(byte,"%x",&tmp);
        bytes[j]=tmp;
    }

}

void printTime(char *vtime){

    time_t t;
    struct tm *aTime;

    time(&t);
    aTime = localtime(&t);

    sprintf (vtime,"\n%02d/%02d/%d - %02d:%02d:%02d\n", aTime->tm_mday, 1 + aTime->tm_mon, 1900 + aTime->tm_year, aTime->tm_hour, aTime->tm_min, aTime->tm_sec);

}


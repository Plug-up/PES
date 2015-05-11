/*
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/

#include <string.h>
#include "hidapi.h"
#include "util.h"

#define T_BLOC 64 //bloc size (report)
#define SIZE_BYTES_APDU (255+6) //255 : max data //6 : apdu header
#define SIZE_BYTES_APDU_REP_DATA 255 //255 : max data


void exchangeApdu(hid_device *,const char *,char *, char*);

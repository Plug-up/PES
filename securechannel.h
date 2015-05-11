/*
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/

#include "sc_functions.h"
#include "communication.h"
#include "common.h"
#define SUCCESS 1
#define SECURITY_LEVEL "01" //CMAC


int openSecureChannel(hid_device *plug_up,char* keysetId, char *div_key, char* c_macKey, char* c_mac, char *s_dekKey);

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *str_sub (const char *, unsigned int, unsigned int);

/*
transform a bytes array to a string
*/
void bytesToString(unsigned char *bytes,int t_bytes,char *string);

/*
transform a string to bytes array
*/
void stringToBytes(const char *string, unsigned char *bytes);

//system time
void printTime(char *vtime);

#endif // UTIL_H


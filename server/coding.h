#ifndef _CODING_H
#define _CODING_H

int decoding(char* in, int inlen, char** out, int* outlen);

int encoding(char* in, int inlen, char** out, int* outlen);

int init_coding();

#endif

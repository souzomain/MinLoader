#ifndef MINISTD_H
#define MINISTD_H

#include <wchar.h>
#include "inc.h"

int StringCompareInsensitiveA(const char *String1,const char *String2 );
void MemSet( void *Destination, int Val, unsigned long Size );
unsigned long CharStringToWCharString(wchar_t *Dstination, char *Source, unsigned long MaxAllowed);
unsigned long StringLengthA(const char *String );
int StringCompareA(const char *String1,const char *String2 );
unsigned long WCharStringToCharString( char *Destination, wchar_t *Source, unsigned long MaximumAllowed );
int StringNCompareInsensitiveA(const char *s1, const char *s2, size_t n);
#define _ZeroMemory(x,y) MemSet(x,0,y)
#endif

#ifndef MINISTD_H
#define MINISTD_H

#include <wchar.h>
#include "inc.h"

int StringNCompareInsensitiveA(const char *s1, const char *s2, size_t n);
int StringNCompareA(const char *String1, const char *String2, size_t n);
int FindStringA(const char *str, const char *delimiter);
int StringCompareA(const char *String1,const char *String2 );
int StringCompareInsensitiveA(const char *String1,const char *String2 );
int MemCompare( void *s1, void *s2, int len );
char *StringCopyA( char *String1, char *String2 );
void MemSet( void *Destination, int Val, unsigned long Size );
void *CopyMemory(void *Destination, const void *Source, unsigned long Size);
unsigned long StringLengthA(const char *String );
unsigned long StringLengthW(wchar_t *String);
unsigned long WCharStringToCharString( char *Destination, wchar_t *Source, unsigned long MaximumAllowed );
unsigned long CharStringToWCharString(wchar_t *Destination, char *Source, unsigned long MaxAllowed);
bool isalfanum(const char C);

#define _ZeroMemory(x,y) MemSet(x,0,y)
#endif

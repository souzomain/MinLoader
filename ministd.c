#include "ministd.h"

char tolower_cus(char c){
    if(c>='A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

int StringNCompareInsensitiveA(const char *s1, const char *s2, size_t n){
    for (size_t i = 0; i < n; i++) {
        if (tolower_cus(s1[i]) != tolower_cus(s2[i])) {
            return (tolower_cus(s1[i]) < tolower_cus(s2[i])) ? -1 : 1;
        }
        else if (s1[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

int StringCompareA(const char *String1,const char *String2 ){
    for (;*String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(char *)String1 < *(char *)String2) ? -1 : +1);
}

int StringCompareInsensitiveA(const char *String1, const char *String2 ){
    for (;tolower_cus(*String1) == tolower_cus(*String2); String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return (tolower_cus(*String1) < tolower_cus(*String2) ? -1 : 1);
}


unsigned long StringLengthA(const char *String ){
    char *String2;

    if ( String == NULL)
        return 0;

    for (String2 = (char *)String; *String2; ++String2);

    return (String2 - String);
}

unsigned long WCharStringToCharString( char *Destination, wchar_t *Source, unsigned long MaximumAllowed ){
    int Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

unsigned long CharStringToWCharString(wchar_t *Destination, char *Source, unsigned long MaxAllowed){
    int Length = MaxAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaxAllowed - Length - 1;
    }

    return MaxAllowed - Length;
}

void MemSet( void *Destination, int Val, unsigned long Size ){
    int i = 0;
    unsigned char *p = (unsigned char*)Destination;
    while(Size>0){
        *p= Val;
        ++p;
        --Size;
    }
}

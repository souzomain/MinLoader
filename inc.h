#ifndef INC_H
#define INC_H


#ifdef DEBUG
#include <stdio.h>
#define MSG(fmt, args...) do { fprintf(stderr, "FILE: %s | Line: %d | Function: %s " fmt "\n", __FILE__, __LINE__, __func__ , ## args); } while(0)
#else
#define MSG(fmt, args...) do {} while (0)
#endif

typedef enum _bool 
{
    false = 0,true = 1
} bool;

#endif

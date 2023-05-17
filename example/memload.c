#include "../loader.h"
#include <stdio.h>

int main(int argc, char *argv[]){
    
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    int len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = NtAllocateHeap(len);
    fread(data, len, 1, f);

    void *pmain = loader_get_entrypoint(data);

    if(!pmain){
        MSG("Can'not load the buffer");
        return false;
    }
    
    MSG("Calling main from %p",pmain);

    ((int (*)(int,char**))pmain)(argc, argv);
    
    return true;
}

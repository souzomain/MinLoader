#ifndef LOADER_H
#define LOADER_H

#include "inc.h"
#include "winapi.h"


typedef struct ImageLoader{
    PCHAR ICode;
    size_t Image;
    size_t deltaAddr;

    size_t ImageBase;
    size_t Entrypoint;

    PIMAGE_DOS_HEADER DosHdr;
    PIMAGE_NT_HEADERS NtHdr;

    PIMAGE_DATA_DIRECTORY dataDir;
    PIMAGE_SECTION_HEADER sections;
    DWORD sizeOfHeaders;
    DWORD sizeOfImage;

    api_loader_h *LoaderAPI;

}IMAGE_LOADER, *PIMAGE_LOADER;

PVOID loader_get_entrypoint(char *data);

PIMAGE_LOADER loader_load_image(char *code);

bool loader_fix_sections(PIMAGE_LOADER ILoader);

bool loader_fix_IAT(PIMAGE_LOADER ILoader);

bool loader_fix_reloc(PIMAGE_LOADER ILoader);

bool loader_call_tls(PIMAGE_LOADER ILoader);

bool loader_end_image(PIMAGE_LOADER ILoader);

bool loader_set_winhook(PIMAGE_LOADER linfo,const char *winapi, void *addr);

#endif


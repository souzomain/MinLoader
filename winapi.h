#ifndef S_WINAPI_H
#define S_WINAPI_H

#include "ntdll.h"


#define WAPI(x) __typeof__(x) *x;

typedef struct {
    WAPI(LdrLoadDll);
    WAPI(LdrGetProcedureAddress);
    WAPI(NtAllocateVirtualMemory);
    WAPI(NtFreeVirtualMemory);
    WAPI(NtProtectVirtualMemory);
}api_loader_h;


void *          LdrLoadModule(api_loader_h *api, const char *module);
void *          LdrGetFunc(api_loader_h *api, void *module, const char *func);
void *          GetModuleFromPeb(const char *module);
api_loader_h *  new_loaderapi();

PTEB GetTeb(void);
PPEB GetPebFromTeb(void);

PVOID NtCurrentHeap();
PVOID NtAllocateHeap(size_t size);
void  NtFreeHeap(PVOID ptr);

#endif

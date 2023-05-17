#include "ministd.h"
#include "winapi.h"

char ntdll[] = "ntdll";
char kernel32[] = "kernel32";


//TODO: change from str to function hash
api_loader_h *new_loaderapi(){

    void *ntdll_module      = GetModuleFromPeb(ntdll);
    void *kernel32_module   = GetModuleFromPeb(kernel32);

    api_loader_h *LoaderAPI = (api_loader_h *)NtAllocateHeap(sizeof(api_loader_h));

    //TODO: change function name to hash
    LoaderAPI->LdrGetProcedureAddress    = LdrGetFunc(NULL, ntdll_module,      "LdrGetProcedureAddress"); 
    LoaderAPI->LdrLoadDll                = LdrGetFunc(NULL, ntdll_module,      "LdrLoadDll");
    
    //syscalls
    LoaderAPI->NtAllocateVirtualMemory   = LdrGetFunc(LoaderAPI, ntdll_module,      "NtAllocateVirtualMemory");
    LoaderAPI->NtFreeVirtualMemory       = LdrGetFunc(LoaderAPI, ntdll_module,      "NtFreeVirtualMemory");
    LoaderAPI->NtProtectVirtualMemory    = LdrGetFunc(LoaderAPI, ntdll_module,      "NtProtectVirtualMemory");

    return LoaderAPI;
}

void *LdrLoadModule(api_loader_h *api, const char *module){
    if(!module || !api) return NULL;
    void *mod = GetModuleFromPeb(module);
    if(mod) return mod;
    
    UNICODE_STRING DllPath  = {0};
    void *PModule           = NULL;
    size_t ModStrlen        = 0;
    NTSTATUS status         = 0;
    wchar_t wModule[MAX_PATH + 1];

    ModStrlen = StringLengthA(module);
    CharStringToWCharString(wModule, (char *)module, ModStrlen);

    DllPath.Buffer          = wModule;
    DllPath.Length          = (ModStrlen) * sizeof(WCHAR);
    DllPath.MaximumLength   = (ModStrlen + 1) * sizeof(WCHAR);

    status = api->LdrLoadDll(NULL, NULL, &DllPath, &PModule);
    if(NT_SUCCESS(status))
        return PModule;

    return NULL;
}

void *LdrGetFunc(api_loader_h *api, void *module, const char *func){
    if(!module)
        return NULL;
    
    PIMAGE_DOS_HEADER dos                   = NULL;
    PIMAGE_NT_HEADERS nt                    = NULL;
    PIMAGE_FILE_HEADER file                 = NULL;
    PIMAGE_OPTIONAL_HEADER optional         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID FuncAddr                          = NULL;
    DWORD ExportDirectorySize               = 0;
    PDWORD AddrOfNames                      = NULL;
    PDWORD AddrOfFunctions                  = NULL;
    PWORD AddrOfOrdinals                    = NULL;
    ANSI_STRING AnsiStr                     = { 0 };
    char *FuncName;

    dos      = (PIMAGE_DOS_HEADER)module;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    
    nt       = (PIMAGE_NT_HEADERS)((BYTE *)module + dos->e_lfanew);
    file     = (PIMAGE_FILE_HEADER)((BYTE *)module + dos->e_lfanew + sizeof(DWORD));
    optional = (PIMAGE_OPTIONAL_HEADER)((BYTE *)file + sizeof(IMAGE_FILE_HEADER));

    ExportDirectory         = (IMAGE_EXPORT_DIRECTORY *) ((size_t)module + nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress);

    AddrOfNames             = (PDWORD) ((size_t) module + ExportDirectory->AddressOfNames);
    AddrOfFunctions         = (PDWORD) ((size_t) module + ExportDirectory->AddressOfFunctions);
    AddrOfOrdinals          = (PWORD)  ((size_t) module + ExportDirectory->AddressOfNameOrdinals);

    for(DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i){
        FuncName = (char *)((size_t)module + AddrOfNames[i]);
        if(StringCompareA((char *)func,FuncName) == 0){
            FuncAddr = (PVOID)((size_t)module + AddrOfFunctions[AddrOfOrdinals[i]]);
            if(!FuncAddr) goto EXIT;
            if(
                    (ULONG_PTR) FuncAddr >= (ULONG_PTR)ExportDirectory &&
                    (ULONG_PTR) FuncAddr < (ULONG_PTR)ExportDirectory + (ULONG_PTR)((size_t)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
            )
            {
                if(!api) { MSG("NO API LOADER");return NULL;}

                AnsiStr.Buffer          = FuncName;
                AnsiStr.Length          = StringLengthA(FuncName);
                AnsiStr.MaximumLength   = AnsiStr.Length + sizeof(CHAR);
                if(!NT_SUCCESS(api->LdrGetProcedureAddress(module,&AnsiStr,0,&FuncAddr)))
                    goto EXIT;
            }
            return FuncAddr;
        }
    }
EXIT:
    MSG("Function not found! %s",func);
    return NULL;
}

void *GetModuleFromPeb(const char *module){
    int dllloc = 0;

    PLDR_DATA_TABLE_ENTRY Ldr   = NULL;
    PLIST_ENTRY Hdr             = NULL, 
                Ent             = NULL;
    PPEB Peb                    = NULL;

    char Unichar[MAX_PATH + 1];

    int module_length = StringLengthA(module);

    Peb = GetPebFromTeb();
    Hdr = &Peb->Ldr->InLoadOrderModuleList;
    Ent = Hdr->Flink;
    for(; Hdr != Ent; Ent = Ent->Flink){
        Ldr = (PLDR_DATA_TABLE_ENTRY)Ent;
        WCharStringToCharString(Unichar, Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length);
        if(StringNCompareInsensitiveA(Unichar, module, module_length) == 0){
            MSG("MODULE: %s FOUND", module);
            return Ldr->DllBase;
        }
    }

    return NULL;
}

PTEB GetTeb(void){
#ifdef _WIN64
    return (PTEB)__readgsqword(0x30);
#elif defined(_WIN32)
    return (PTEB)__readfsdword(0x18);
#endif
}

PPEB GetPebFromTeb(void){
    return (PPEB)GetTeb()->ProcessEnvironmentBlock;
}


PVOID NtCurrentHeap(){
    return GetPebFromTeb()->ProcessHeap;
}

__typeof__(RtlAllocateHeap) *RtlAllocate = NULL;
__typeof__(RtlFreeHeap) *RtlFree = NULL;

PVOID NtAllocateHeap(size_t size){
    if(!RtlAllocate){
        void *_ntdll = GetModuleFromPeb(ntdll);
        RtlAllocate = LdrGetFunc(NULL, _ntdll, "RtlAllocateHeap");
    }
    return RtlAllocate(NtCurrentHeap(), HEAP_ZERO_MEMORY, size);
}

void NtFreeHeap(PVOID ptr){
    if(!RtlFree){
        void *_ntdll = GetModuleFromPeb(ntdll);
        RtlFree = LdrGetFunc(NULL, _ntdll, "RtlFreeHeap");
    }
    RtlFree(NtCurrentHeap(), 0, ptr);
}

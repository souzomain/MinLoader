#include "ministd.h"
#include "loader.h"

#define RVA2VA(mod, rva, type ) ((type)(((size_t) mod) + rva))
typedef struct _BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

PIMAGE_LOADER loader_load_image(char *code){
    MSG("CheckImage");
    PIMAGE_LOADER ILoader = (PIMAGE_LOADER)NtAllocateHeap(sizeof(IMAGE_LOADER));
    api_loader_h *LoaderAPI = new_loaderapi();
    
    if(!code || !LoaderAPI){
        MSG("Error");
        return NULL;
    }

    ILoader->ICode = code;
    ILoader->DosHdr = (PIMAGE_DOS_HEADER)code;
    ILoader->NtHdr  = (PIMAGE_NT_HEADERS)(code + ILoader->DosHdr->e_lfanew); 

    if(ILoader->DosHdr->e_magic != IMAGE_DOS_SIGNATURE || ILoader->NtHdr->Signature != IMAGE_NT_SIGNATURE) {MSG("Error in signature of code"); return NULL;};

    ILoader->sizeOfHeaders   = ILoader->NtHdr->OptionalHeader.SizeOfHeaders;
    ILoader->sizeOfImage     = ILoader->NtHdr->OptionalHeader.SizeOfImage;
    ILoader->dataDir         = ILoader->NtHdr->OptionalHeader.DataDirectory;
    ILoader->ImageBase       = ILoader->NtHdr->OptionalHeader.ImageBase;

    MSG("Allocating memory for image");
    
    SIZE_T regsize = ILoader->sizeOfImage;
    PVOID alloc = (PVOID)ILoader->ImageBase;
    NTSTATUS stat = LoaderAPI->NtAllocateVirtualMemory(NtCurrentProcess(), &alloc, 0, &regsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                                                                                                                                         
    if(!NT_SUCCESS(stat)){
        MSG("Can'not allocate image at ImageBase, size: %d", ILoader->sizeOfImage);
        alloc = NULL;
        stat = LoaderAPI->NtAllocateVirtualMemory(NtCurrentProcess(), &alloc, 0, &regsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(!NT_SUCCESS(stat)){
            MSG("Can'not allocate image, size: %d", ILoader->sizeOfImage);
            return NULL;
        }else{
            ILoader->Image = (size_t)alloc;
            MSG("Loaded image at %p", ILoader->Image);
        }
    }else{
        ILoader->Image = (size_t)alloc;
        MSG("Loaded image at %p", ILoader->Image);
    }

    ILoader->deltaAddr = ILoader->Image - ILoader->NtHdr->OptionalHeader.ImageBase;

    CopyMemory((PVOID)ILoader->Image, (PVOID)code, ILoader->NtHdr->OptionalHeader.SizeOfHeaders);

    PIMAGE_NT_HEADERS loadedNtHdr = (PIMAGE_NT_HEADERS)(ILoader->Image + ILoader->DosHdr->e_lfanew);
    loadedNtHdr->OptionalHeader.ImageBase = ILoader->Image;
    
    ILoader->sections = (PIMAGE_SECTION_HEADER)((char *)&ILoader->NtHdr->OptionalHeader + ILoader->NtHdr->FileHeader.SizeOfOptionalHeader);
    ILoader->LoaderAPI = LoaderAPI;
    
    return ILoader;
}

bool loader_fix_sections(PIMAGE_LOADER ILoader){
    if(!ILoader || !ILoader->NtHdr) return false;
    
    MSG("Fixing sections");
    for(int i = 0; i < ILoader->NtHdr->FileHeader.NumberOfSections; ++i){
        
        PVOID dest = RVA2VA(ILoader->Image,ILoader->sections[i].VirtualAddress,PVOID);
        if(ILoader->sections[i].SizeOfRawData > 0){
            MSG("Copy PointerToRawData to section [ %s ]",ILoader->sections[i].Name);
            CopyMemory(dest,(char *)ILoader->ICode + ILoader->sections[i].PointerToRawData, ILoader->sections[i].SizeOfRawData);
        }
        else{
            MSG("zero destination virtualmemory from section [ %s ]",ILoader->sections[i].Name);
            MemSet(dest,0,ILoader->sections[i].Misc.VirtualSize); 
        }
    }
    MSG("Sections fixed!\n");
    return true;
}

bool loader_fix_IAT(PIMAGE_LOADER ILoader){
    if(!ILoader) return false;

    PIMAGE_IMPORT_DESCRIPTOR iDesc = NULL;
    
    MSG("loader_fix_IAT");
    if(ILoader->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size && ILoader->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        iDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ILoader->Image + ILoader->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    else return false;

    while(iDesc->Name){
        LPCSTR ModuleName   = NULL;
        HMODULE ModuleBase  = NULL;

        PIMAGE_THUNK_DATA original = NULL, first = NULL;

        ModuleName = (PCHAR)(ILoader->Image + iDesc->Name);

        MSG("Loading Module: %s", ModuleName);
        
        ModuleBase = LdrLoadModule(ILoader->LoaderAPI, ModuleName); 
        if(!ModuleBase){ MSG("Can'not get module!"); goto MODULE; }

        if(iDesc->OriginalFirstThunk)
            original = (PIMAGE_THUNK_DATA)(ILoader->Image + iDesc->OriginalFirstThunk);
        else
            original =  (PIMAGE_THUNK_DATA)(ILoader->Image + iDesc->FirstThunk);
        
        first = (PIMAGE_THUNK_DATA)(ILoader->Image + iDesc->FirstThunk);

        while(original->u1.AddressOfData != 0){

            FARPROC *addr;
            
            if(original->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                addr = (FARPROC *)LdrGetFunc(ILoader->LoaderAPI, ModuleBase, (LPCSTR)(original->u1.Ordinal & 0xFFFF));
 //               MSG("FUNCION LOADED: %s", (LPCSTR)(original->u1.Ordinal & 0xFFFF));
            } else{
                PIMAGE_IMPORT_BY_NAME FuncName  = (PIMAGE_IMPORT_BY_NAME)(ILoader->Image + original->u1.AddressOfData);
                addr = (FARPROC *)LdrGetFunc(ILoader->LoaderAPI, ModuleBase, (LPCSTR)FuncName->Name);
 //               MSG("FUNCION LOADED: %s", (LPCSTR)FuncName->Name);
            }

            first->u1.Function = (size_t)addr;

            NEXT_FUNCTION:
            ++original;
            ++first;
        }
        MODULE:
        ++iDesc;
    }
    MSG("IAT Fixed!\n");
    return true;
}

bool loader_fix_reloc(PIMAGE_LOADER ILoader){
    MSG("loader_fix_reloc");

    if(!ILoader) return false;

    if(!ILoader->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size){
        MSG("Error on reloc!");
        return true;
    }

    PIMAGE_BASE_RELOCATION p_reloc = (PIMAGE_BASE_RELOCATION)(ILoader->Image + ILoader->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while(p_reloc->VirtualAddress > 0){
        size_t ptr = (size_t)(ILoader->Image + p_reloc->VirtualAddress);
        PBASE_RELOCATION_ENTRY rinfo = (PBASE_RELOCATION_ENTRY)(((size_t) p_reloc) + sizeof(IMAGE_BASE_RELOCATION));
  
        for(int x = 0; x < (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY); x++, rinfo++)
         {
            switch(rinfo->Type)
            {
               case IMAGE_REL_BASED_DIR64:
                  *((size_t*)(ptr + rinfo->Offset))   += ILoader->deltaAddr;
                  break;   

               case IMAGE_REL_BASED_HIGHLOW:
                  *((DWORD*)(ptr + rinfo->Offset))    += (DWORD)ILoader->deltaAddr;
                  break;

               case IMAGE_REL_BASED_HIGH:
                  *((WORD*)(ptr + rinfo->Offset))     += HIWORD(ILoader->deltaAddr);
                  break;

               case IMAGE_REL_BASED_LOW:
                  *((WORD*)(ptr + rinfo->Offset))     += LOWORD(ILoader->deltaAddr);
                  break;

               case IMAGE_REL_BASED_ABSOLUTE:
                  break;

               default:
                  MSG("Unknown relocation type: 0x%08x", rinfo->Type);
                  break;
            }
         }
         p_reloc = (PIMAGE_BASE_RELOCATION)((char *)p_reloc + p_reloc->SizeOfBlock);
    }
    MSG("Reloc Fixed!");
    return true;
}

bool loader_call_tls(PIMAGE_LOADER ILoader){
    MSG("Calling TLS");

    if(!ILoader) return false;

    if(!ILoader->NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) return true;
    
    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(ILoader->Image + ILoader->NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if(!tls){ MSG("TLS error!"); return true;};
    PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    PIMAGE_TLS_CALLBACK test = (PIMAGE_TLS_CALLBACK)tls->AddressOfCallBacks;
    
    while(*callback)
    {
        MSG("TLS Callback: %p", callback);
        (*callback)((PVOID)ILoader->Image, DLL_PROCESS_ATTACH, NULL);
        callback++;
    }
    
    return true;
}

bool loader_end_image(PIMAGE_LOADER ILoader){
    MSG("fixing sections memory");
    if(!ILoader) return false;
    for(int x = 0; x < ILoader->NtHdr->FileHeader.NumberOfSections; x++)
    {
        DWORD oldFlags;
        DWORD flags = 0;

        if(ILoader->sections[x].Characteristics & IMAGE_SCN_MEM_READ)
            flags |= PAGE_READONLY;

        if(ILoader->sections[x].Characteristics & IMAGE_SCN_MEM_WRITE)
            flags |= PAGE_READWRITE;

        else if(ILoader->sections[x].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            flags |= PAGE_EXECUTE;

        //ILoader->LoaderAPI->VirtualProtect((char *)ILoader->Image + ILoader->sections[x].VirtualAddress, ILoader->sections[x].Misc.VirtualSize, flags, &oldFlags);
        PVOID baddr = (void *)ILoader->Image + ILoader->sections[x].VirtualAddress;
        SIZE_T csize = ILoader->sections[x].Misc.VirtualSize;
        ILoader->LoaderAPI->NtProtectVirtualMemory(NtCurrentProcess(), &baddr, &csize, flags, &oldFlags);
    }
    return true;
}

bool loader_set_winhook(PIMAGE_LOADER linfo,const char *winapi, void *addr){
    if(!linfo || !linfo->NtHdr ) return false;
    
    PIMAGE_IMPORT_DESCRIPTOR iDesc = NULL;
    
    MSG("loader_fix_IAT");
    if(linfo->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size && linfo->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        iDesc = (PIMAGE_IMPORT_DESCRIPTOR)(linfo->Image + linfo->dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    else return false;

    MSG("loader_set_winhook");
    
    while(iDesc->Name){
        LPCSTR ModuleName   = NULL;

        PIMAGE_THUNK_DATA original = NULL, first = NULL;

        ModuleName = (PCHAR)(linfo->Image + iDesc->Name);

        if(iDesc->OriginalFirstThunk)
            original = (PIMAGE_THUNK_DATA)(linfo->Image + iDesc->OriginalFirstThunk);
        else
            original =  (PIMAGE_THUNK_DATA)(linfo->Image + iDesc->FirstThunk);
        
        first = (PIMAGE_THUNK_DATA)(linfo->Image + iDesc->FirstThunk);

        while(original->u1.AddressOfData != 0){

            FARPROC *addr;
            char *FuncName;
            if(original->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                FuncName = (char *)(original->u1.Ordinal & 0xFFFF);
            else
                FuncName = ((PIMAGE_IMPORT_BY_NAME)(linfo->Image + original->u1.AddressOfData))->Name;

            if(StringCompareInsensitiveA(winapi, FuncName) == 0){
                MSG("Function: %s\nModule Found: %s\n",FuncName, ModuleName);
                first->u1.Function = (size_t)addr;
                return true;
            }
            NEXT_FUNCTION:
            ++original;
            ++first;
        }
        MODULE:
        ++iDesc;
    }
    return true;
}

//load code and return entrypoint
PVOID loader_get_entrypoint(PCHAR code){

    if(!code){ MSG("No code are provided"); return NULL;}

    MSG("[+] Souzo Loader ");

    PIMAGE_LOADER loadInfo = loader_load_image(code);
    if(!loadInfo){
        MSG("Can'not load the image.");
        return NULL;
    }

    loader_fix_sections(loadInfo); 
    loader_fix_IAT(loadInfo); 
    loader_fix_reloc(loadInfo); 
    loader_call_tls(loadInfo);
    loader_end_image(loadInfo);

    return (void *)loadInfo->Image + loadInfo->NtHdr->OptionalHeader.AddressOfEntryPoint;
}

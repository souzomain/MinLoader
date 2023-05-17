#MinLoader

This project is a minimal PE Loader writed in c.

This project is very minimal and is interesting to be used for studies purposes.

Functions from Loader:

```c
PVOID loader_get_entrypoint(char *data);
PIMAGE_LOADER loader_load_image(char *code);
bool loader_fix_sections(PIMAGE_LOADER ILoader);
bool loader_fix_IAT(PIMAGE_LOADER ILoader);
bool loader_fix_reloc(PIMAGE_LOADER ILoader);
bool loader_call_tls(PIMAGE_LOADER ILoader);
bool loader_end_image(PIMAGE_LOADER ILoader);
bool loader_set_winhook(PIMAGE_LOADER linfo,const char *winapi, void *addr);
```

On folder example, you can see an example of how to use the loader.

good studies :)

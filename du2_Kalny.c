// du2_Kalny.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

void* (*original_malloc)(size_t size); // should this be void* or ULONGULONG*? idk
void* (*original_realloc)(void*ptr, size_t new_size);
void* (*original_calloc)(size_t num, size_t size);
void* original_free;
void** IAT_ENTRIES[5]; // malloc, realloc, calloc, free

DWORD oldprotect;

typedef struct AllocationRecord {
    int i;
    size_t size;
    void* ptr;
}AllocationRecord;

AllocationRecord allocated_memory[1000];

void initialise_allocation_records() {
    for (int i = 0; i < size(allocated_memory); i++) {
        allocated_memory[i].i = i;
        allocated_memory[i].size = 0;
        allocated_memory[i].ptr = NULL;
    }
}

void* MallocDebug_malloc(size_t size);
void* MallocDebug_realloc(void* ptr, size_t new_size);

PIMAGE_NT_HEADERS get_NT_Headers() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means current process
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    printf("Address of hPEFile: %p\n", (void*)hPEFile);
    printf("Starting address of the process %p\n", (BYTE*)pDosHeader);
    // pDosHeader->e_lfanew RVA 
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);
    return pNTHeaders;
}
void MallocDebug_Done() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means current process
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    while (pImportDescriptor < pImportDescriptorEnd && pImportDescriptor->Name != 0) {
        // Get first thunk IAT, this one is gonna be rewritten with addresses of our functions
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->FirstThunk + ((BYTE*)pDosHeader));
        // Get the original first thunk (INT)
        IMAGE_THUNK_DATA* pOriginalThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->OriginalFirstThunk + ((BYTE*)pDosHeader));

        // Get imported functions
        while (pOriginalThunk->u1.AddressOfData != 0) {
            if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // Import by name
                IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pOriginalThunk->u1.AddressOfData + (BYTE*)pDosHeader);
                if (strcmp(pImportByName->Name, "malloc") == 0) {
                    VirtualProtect(IAT_ENTRIES[0], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_malloc;
                    VirtualProtect(IAT_ENTRIES[0], sizeof(DWORD), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "realloc") == 0) {
                    VirtualProtect(IAT_ENTRIES[1], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_realloc;
                    VirtualProtect(IAT_ENTRIES[1], sizeof(DWORD), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "calloc") == 0) {
                    irtualProtect(IAT_ENTRIES[2], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_calloc;
                    VirtualProtect(IAT_ENTRIES[2], sizeof(DWORD), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "free") == 0) {
                    irtualProtect(IAT_ENTRIES[3], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_free;
                    VirtualProtect(IAT_ENTRIES[3], sizeof(DWORD), oldprotect, &oldprotect);
                }
            }
            pOriginalThunk++;
            pThunk++;
        }
        // IMAGE_IMPORT_BY_NAME* imgImport_By_name = (IMAGE_IMPORT_BY_NAME*)(pThunk->u1.AddressOfData + (BYTE*)pDosHeader);
        pImportDescriptor++;
    }
    return 0;
}

int MallocDebug_Init() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means current process
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    printf("Address of hPEFile: %p\n", (void*)hPEFile);
    printf("Starting address of the process %p\n", (BYTE*)pDosHeader);
    // pDosHeader->e_lfanew RVA 
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);

    // We are going to iterate over this one
    // pointer to first image_import_descriptor 
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // pointer to very last image_import descriptor which no longer exists
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    while (pImportDescriptor < pImportDescriptorEnd && pImportDescriptor->Name != 0) {
        char* dll_library_name = (char*)(pImportDescriptor->Name + ((BYTE*)pDosHeader));
        printf("%s\n", dll_library_name);

        // Get first thunk IAT, this one is gonna be rewritten with addresses of our functions
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->FirstThunk + ((BYTE*)pDosHeader));
        // Get the original first thunk (INT)
        IMAGE_THUNK_DATA* pOriginalThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->OriginalFirstThunk + ((BYTE*)pDosHeader));

        // Get imported functions
        while (pOriginalThunk->u1.AddressOfData != 0) {
            if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // Import by name
                IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pOriginalThunk->u1.AddressOfData + (BYTE*)pDosHeader);

                //
                //  **MALLOC**
                //
                if (strcmp(pImportByName->Name, "malloc") == 0) {
                    // Get the original address of malloc function
                    original_malloc = (void *)pThunk->u1.Function;
                    
                    // Get address of malloc function in the IAT table
                    IAT_ENTRIES[0] = (void**)&(pThunk->u1.Function);

                    printf("Original malloc address: %p\n",(void*) pThunk->u1.Function);
                    printf("Address of malloc in IAT table %p\n", &(pThunk->u1.Function));
                    printf("Address of our malloc function %p\n", MallocDebug_malloc);
                    
                    // Change the address 
                    VirtualProtect(IAT_ENTRIES[0], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = MallocDebug_malloc;
                    VirtualProtect(IAT_ENTRIES[0], sizeof(DWORD), oldprotect, &oldprotect);
                }
                //
                //  **MALLOC**
                //
                if (strcmp(pImportByName->Name, "realloc") == 0) {
                    // Get the original address of malloc function
                    original_realloc = (void*)pThunk->u1.Function;

                    // Get address of malloc function in the IAT table
                    IAT_ENTRIES[1] = (void**)&(pThunk->u1.Function);

                    // Change the address 
                    VirtualProtect(IAT_ENTRIES[1], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[1]) = MallocDebug_realloc;
                    VirtualProtect(IAT_ENTRIES[1], sizeof(DWORD), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "calloc") == 0) {
                    original_calloc = (void*)pThunk->u1.Function;
                    IAT_ENTRIES[2] = (void**)&(pThunk->u1.Function);

                    VirtualProtect(IAT_ENTRIES[2], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[2]) = MallocDebug_realloc;
                    VirtualProtect(IAT_ENTRIES[2], sizeof(DWORD), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "free") == 0) {
                    original_calloc = (void*)pThunk->u1.Function;
                    IAT_ENTRIES[3] = (void**)&(pThunk->u1.Function);

                    VirtualProtect(IAT_ENTRIES[3], sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[3]) = MallocDebug_realloc;
                    VirtualProtect(IAT_ENTRIES[3], sizeof(DWORD), oldprotect, &oldprotect);
                }
            }
            else {
                // Import by ordinal
                // printf("\tImported by ordinal %lld\n", pOriginalThunk->u1.Ordinal & 0xFFFF);
            }
            pOriginalThunk++;
            pThunk++;
        }
        // IMAGE_IMPORT_BY_NAME* imgImport_By_name = (IMAGE_IMPORT_BY_NAME*)(pThunk->u1.AddressOfData + (BYTE*)pDosHeader);
        pImportDescriptor++;
    }
    return 0;
}

void* MallocDebug_malloc(size_t size) {
    printf("This is my malloc");
    void* p = original_malloc(size);
    return p;
}

void* MallocDebug_realloc(void* ptr, size_t new_size) {
    return ptr;
}
void* MallocDebug_calloc(size_t num, size_t size) {
    return NULL;
}
void* MallocDebug_free(void* ptr) {
    return NULL;
}

int main()
{
    initialise_allocation_records();
    MallocDebug_Init();
    void* test = malloc(100);
    free(test);
    return 0;
}



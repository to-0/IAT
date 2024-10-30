// du2_Kalny.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

void* (*original_malloc)(size_t size) = NULL; // should this be void* or ULONGULONG*? idk
void* (*original_realloc)(void*ptr, size_t new_size) = NULL;
void* (*original_calloc)(size_t num, size_t size) = NULL ;
void (*original_free)(void *ptr) = NULL;
void** IAT_ENTRIES[5] = {NULL}; // malloc, realloc, calloc, free
#define ARR_SIZE 1000
DWORD oldprotect;

typedef struct AllocationRecord {
    char allocated;
    size_t size;
    void* ptr;
}AllocationRecord;

AllocationRecord allocated_memory[ARR_SIZE];
int counter = 0;
void initialise_allocation_records() {
    for (int i = 0; i < ARR_SIZE; i++) {
        allocated_memory[i].allocated = 'n';
        allocated_memory[i].size = (size_t) 0;
        allocated_memory[i].ptr = NULL;
    }
}

void* MallocDebug_malloc(size_t size);
void* MallocDebug_realloc(void* ptr, size_t new_size);
void MallocDebug_free(void* ptr);
void* MallocDebug_calloc(size_t num, size_t size);


int MallocDebug_Done() {
    int n_leaks = check_leaky_memory();
    printf("%d leak(s) identified\n", n_leaks);

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
                    if (original_malloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    VirtualProtect(IAT_ENTRIES[0], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_malloc;
                    VirtualProtect(IAT_ENTRIES[0], sizeof(void *), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "realloc") == 0) {
                    if (original_realloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    VirtualProtect(IAT_ENTRIES[1], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_realloc;
                    VirtualProtect(IAT_ENTRIES[1], sizeof(void *), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "calloc") == 0) {
                    if (original_calloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    VirtualProtect(IAT_ENTRIES[2], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_calloc;
                    VirtualProtect(IAT_ENTRIES[2], sizeof(void *), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "free") == 0) {
                    if (original_free == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    VirtualProtect(IAT_ENTRIES[3], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = original_free;
                    VirtualProtect(IAT_ENTRIES[3], sizeof(void *), oldprotect, &oldprotect);
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
    MEMORY_BASIC_INFORMATION memory_basic_info;
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
                //  MALLOC
                //
                if (strcmp(pImportByName->Name, "malloc") == 0) {
                    // the function was already found
                    if (original_malloc != NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    // Get the original address of malloc function
                    original_malloc = (void *)pThunk->u1.Function;
                    
                    VirtualQuery(pThunk->u1.Function, &memory_basic_info, sizeof(memory_basic_info));

                    // Get address of malloc function in the IAT table
                    IAT_ENTRIES[0] = (void**)&(pThunk->u1.Function);
                    
                    // Change the address 
                    VirtualProtect(IAT_ENTRIES[0], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[0]) = MallocDebug_malloc;
                    VirtualProtect(IAT_ENTRIES[0], sizeof(void *), oldprotect, &oldprotect);
                }
                //
                //  REALLOC
                //
                if (strcmp(pImportByName->Name, "realloc") == 0) {
                    if (original_realloc != NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    // Get the original address of malloc function
                    original_realloc = (void*)pThunk->u1.Function;

                    // Get address of malloc function in the IAT table
                    IAT_ENTRIES[1] = (void**)&(pThunk->u1.Function);

                    // Change the address 
                    VirtualProtect(IAT_ENTRIES[1], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[1]) = MallocDebug_realloc;
                    VirtualProtect(IAT_ENTRIES[1], sizeof(void *), oldprotect, &oldprotect);
                }
                //
                // CALLOC
                //
                else if (strcmp(pImportByName->Name, "calloc") == 0) {
                    if (original_calloc != NULL) {
                        pOriginalThunk++;
                        continue;
                    }

                    original_calloc = (void*)pThunk->u1.Function;
                    IAT_ENTRIES[2] = (void**)&(pThunk->u1.Function);

                    VirtualProtect(IAT_ENTRIES[2], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[2]) = MallocDebug_calloc;
                    VirtualProtect(IAT_ENTRIES[2], sizeof(void *), oldprotect, &oldprotect);
                }
                //
                // FREE
                //
                else if (strcmp(pImportByName->Name, "free") == 0) {
                    if (original_free != NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    original_free = (void*)pThunk->u1.Function;
                    IAT_ENTRIES[3] = (void**)&(pThunk->u1.Function);
                    VirtualProtect(IAT_ENTRIES[3], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldprotect);
                    *(IAT_ENTRIES[3]) = MallocDebug_free;
                    VirtualProtect(IAT_ENTRIES[3], sizeof(void *), oldprotect, &oldprotect);
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

void* MallocDebug_malloc(size_t size) {
    printf("This is my malloc");
    void* p = original_malloc(size);
    if (counter < ARR_SIZE) {
        if (p == NULL) {
            printf("Failed to allocate memory of size %d\n", (int) size);
            // size -1 means that the allocation failed
            allocated_memory[counter].size = -1;
        }
        else {
            allocated_memory[counter].size = size;
            allocated_memory[counter].ptr = p;
            allocated_memory[counter].allocated = 'y';
        }
    }
    else{
        printf("Maximum number of allocation records exceeded. No logs and leak controls for further allocations from this point.\n");
    }
    counter++;
    return p;
}
// Finds index of Allocated memory
int find_index(void* ptr) {
    for (int i = 0; i < counter; i++) {
        if (allocated_memory[i].ptr == ptr && allocated_memory[i].allocated == 'y') {
            return i;
        }
    }
    return -1;
}

void* MallocDebug_realloc(void* ptr, size_t new_size) {
    int i = find_index(ptr);
    if (i == -1) {
        printf("Unable to find %p in memory", ptr);
        return ptr;
    }
    
    void* ptr2 = original_realloc(ptr, new_size);
    if (ptr2 == NULL) {
        printf("Realloc failed, the original pointer remains");
        return ptr;
    }
    allocated_memory[i].ptr = NULL;
    allocated_memory[i].size = -1;
    allocated_memory[i].allocated = 'n';

    allocated_memory[counter].ptr = ptr2;
    allocated_memory[counter].size = new_size;
    allocated_memory[counter].allocated = 'y';
    counter++;
    return ptr2;
}
int check_leaky_memory() {
    int leaky_count = 0;
    for (int i = 0; i < ARR_SIZE; i++) {
        AllocationRecord* a = &(allocated_memory[i]);
        if (a->allocated == 'y' && a->ptr != NULL) {
            printf("Leak at %p of size %d\n", a->ptr, (int)a->size);
            leaky_count++;
        }
    }
    return leaky_count;
}
void* MallocDebug_calloc(size_t num, size_t size) {
    printf("This is my CALLOC\n");
    void* p = original_calloc(num, size);
    if (counter < ARR_SIZE) {
        if (p == NULL) {
            printf("Failed to allocate memory of size %d\n", (int)(size*num));
            allocated_memory[counter].size = -1;
            return NULL;
        }
        else {
            allocated_memory[counter].size = size*num;
            allocated_memory[counter].ptr = p;
            allocated_memory[counter].allocated = 'y';
            counter++;
        }
    }
    else {
        printf("Maximum number of allocation records exceeded\n");
    }
    
    return p;
}
void MallocDebug_free(void* ptr) {
    int i = find_index(ptr);
    if (i == -1) {
        printf("The pointer to the memory does not exist\n");
    }
    else if (allocated_memory[i].size >= 0) {
        original_free(allocated_memory[i].ptr);
        allocated_memory[i].ptr = NULL;
        allocated_memory[i].size = -1;
        allocated_memory[i].allocated = 'n';
    }
    else {
        printf("Pointer %p cannot be freed because it points to memory that failed to allocate.\n", allocated_memory[i].ptr);
    }
}

int main()
{
    void* ghost = malloc(1);
    initialise_allocation_records();
    MallocDebug_Init();
    MallocDebug_Init();
    MallocDebug_Init();
    void* test = malloc(100);
    void* b = calloc(10, 4);
    free(test);
    free(NULL);
    MallocDebug_Done();
    return 0;
}



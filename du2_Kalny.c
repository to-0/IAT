// du2_Kalny.cpp : .
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>


void* (*original_malloc)(size_t size) = NULL; 
void* (*original_realloc)(void*ptr, size_t new_size) = NULL;
void* (*original_calloc)(size_t num, size_t size) = NULL ;
void (*original_free)(void *ptr) = NULL;
#define ARR_SIZE 2000
#define CHECK_VIRTUAL_PROTECT(ptr, size, newProtect, oldProtect) \
    if (newProtect != NULL){ \
        if (!VirtualProtect(ptr, size, newProtect, oldProtect)) { \
        printf("VirtualProtect failed with error code: %ld\n", GetLastError()); \
        } \
    }
        /*pOriginalThunk++; \
        pThunk++;\
        continue;\*/
        


DWORD oldprotect = NULL;
char static_libName[150] = { "\0" };

typedef struct AllocationRecord {
    size_t size;
    void* ptr;
}AllocationRecord;

AllocationRecord allocation_records[ARR_SIZE];
int counter = 0;
void initialise_allocation_records() {
    for (int i = 0; i < ARR_SIZE; i++) {
        allocation_records[i].size = 0;
        allocation_records[i].ptr = NULL;
    }
}

void* MallocDebug_malloc(size_t size);
void* MallocDebug_realloc(void* ptr, size_t new_size);
void MallocDebug_free(void* ptr);
void* MallocDebug_calloc(size_t num, size_t size);


int MallocDebug_Done() {
    HMODULE hPEFile = GetModuleHandle(NULL); // NULL means current process
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    while (pImportDescriptor < pImportDescriptorEnd && pImportDescriptor->Characteristics != NULL) {
        // Get first thunk IAT, this one is gonna be rewritten with addresses of our functions
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->FirstThunk + ((BYTE*)pDosHeader));
        // Get the original first thunk (INT)
        IMAGE_THUNK_DATA* pOriginalThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->OriginalFirstThunk + ((BYTE*)pDosHeader));
        
        // Check if we are processing ucrtbased library, skip others
        char* libName = (char*)((BYTE*)pDosHeader + pImportDescriptor->Name);
        //strcpy_s(static_libName, libName);
        int i = 0;
        while (libName[i]!='\0') {
            static_libName[i] = tolower(libName[i]);
            i++;
        }
        static_libName[i] = '\0';
        // if library name is not ucrtbased.dll skip, returns 0 when they are equal 
        if (strcmp(static_libName, "ucrtbased.dll") != 0) {
            pImportDescriptor++;
            continue;
        }
        // Get imported functions
        while (pOriginalThunk->u1.AddressOfData != 0) {
            if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                
                // Import by name
                IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pOriginalThunk->u1.AddressOfData + (BYTE*)pDosHeader);
                if (strcmp(pImportByName->Name, "malloc") == 0) {
                    // original malloc was not found yet
                    if (original_malloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG) original_malloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "realloc") == 0) {
                    if (original_realloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG) original_realloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "calloc") == 0) {
                    if (original_calloc == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG)MallocDebug_calloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
                else if (strcmp(pImportByName->Name, "free") == 0) {
                    if (original_free == NULL) {
                        pOriginalThunk++;
                        continue;
                    }
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG) original_free;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
            }
            pOriginalThunk++;
            pThunk++;
        }
        pImportDescriptor++;
    }
    int n_leaks = check_leaky_memory();
    printf("MallocDebug_Done: %d leak(s) identified\n", n_leaks);
    return 0;
}

int MallocDebug_Init() {
    HMODULE hPEFile = GetModuleHandle(NULL); 
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hPEFile;
    // pDosHeader->e_lfanew is RVA 
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);

    // We are going to iterate over this one
    // pointer to first image_import_descriptor 
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // pointer to very last image_import descriptor which no longer exists
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    
    while (pImportDescriptor < pImportDescriptorEnd && pImportDescriptor->Characteristics != NULL) {
        char* dll_library_name = (char*)(pImportDescriptor->Name + ((BYTE*)pDosHeader));
        //printf("%s\n", dll_library_name);

        // Get first thunk IAT, this one is gonna be rewritten with addresses of our functions
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->FirstThunk + ((BYTE*)pDosHeader));
        // Get the original first thunk (INT)
        IMAGE_THUNK_DATA* pOriginalThunk = (IMAGE_THUNK_DATA*)(pImportDescriptor->OriginalFirstThunk + ((BYTE*)pDosHeader));
        // Check if we are processing ucrtbased library, skip others
        char* libName = (char*)((BYTE*)pDosHeader + pImportDescriptor->Name);
        int i = 0;
        while (libName[i] != '\0') {
            static_libName[i] = tolower(libName[i]);
            i++;
        }
        static_libName[i] = '\0';
        if (strcmp(static_libName, "ucrtbased.dll") != 0) {
            pImportDescriptor++;
            continue;
        }
        // Get imported functions
        while (pOriginalThunk->u1.AddressOfData != 0) {
            if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // Import by name
                IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pOriginalThunk->u1.AddressOfData + (BYTE*)pDosHeader);
                //  MALLOC
                if (strcmp(pImportByName->Name, "malloc") == 0) {
                    if ((void*)pThunk->u1.Function == MallocDebug_malloc) {
                        pOriginalThunk++;
                        pThunk++;
                        continue;
                    }
                    // Get the original address of malloc function
                    original_malloc = (void *)pThunk->u1.Function;

                    
                    // Change the address 
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG) MallocDebug_malloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                 
                }
                //  REALLOC
                if (strcmp(pImportByName->Name, "realloc") == 0) {
                    if ((void*)pThunk->u1.Function == MallocDebug_realloc) {
                        pOriginalThunk++;
                        pThunk++;
                        continue;
                    }
                    // Get the original address of malloc function
                    original_realloc = (void*)pThunk->u1.Function;
                    // Change the address 
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG) MallocDebug_realloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
                // CALLOC
                else if (strcmp(pImportByName->Name, "calloc") == 0) {

                    if ((void*)pThunk->u1.Function == MallocDebug_calloc) {
                        pOriginalThunk++;
                        pThunk++;
                        continue;
                    }

                    original_calloc = (void*)pThunk->u1.Function;

                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG)MallocDebug_calloc;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
                // FREE
                else if (strcmp(pImportByName->Name, "free") == 0) {

                    if ((void*)pThunk->u1.Function == MallocDebug_free) {
                        pOriginalThunk++;
                        pThunk++;
                        continue;
                    }
                    original_free = (void*)pThunk->u1.Function;
                    
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), PAGE_READWRITE, &oldprotect);
                    pThunk->u1.Function = (ULONGLONG)MallocDebug_free;
                    CHECK_VIRTUAL_PROTECT(pThunk, sizeof(pThunk), oldprotect, &oldprotect);
                }
            }
            pOriginalThunk++;
            pThunk++;
        }
        pImportDescriptor++;
    }
    return 0;
}

void* MallocDebug_malloc(size_t size) {
    void* p = original_malloc(size);
    if (p == NULL) {
        printf("Malloc: Failed to allocate memory of size %d\n", (int)size);
        // size -1 means that the allocation failed
        return NULL;
    }
    if (counter < ARR_SIZE) {
        allocation_records[counter].size = size;
        allocation_records[counter].ptr = p;
        counter++;
    }
    else{
        printf("Malloc: Maximum number of allocation records exceeded. No logs and leak controls for further allocations from this point.\n");
    }
    return p;
}
// Finds index of allocated memory
int find_index(void* ptr) {
    if (ptr == NULL) {
        return -1;
    }
    for (int i = 0; i < counter; i++) {
        if (allocation_records[i].ptr == ptr) {
            return i;
        }
    }
    //Unknown
    return -1;
}
void* MallocDebug_realloc(void* ptr, size_t new_size) {
    int i = find_index(ptr);
    void* ptr2 = original_realloc(ptr, new_size);

    if (ptr == NULL) {
        printf("Realloc: Ptr argument is NULL; realloc acts as malloc(%d).\n", (int)new_size);
        // Realloc (malloc) succeeded
        if (ptr2 != NULL && counter < ARR_SIZE) {
            printf("Realloc: Block of size %d has been allocated at %p\n", (int)new_size, ptr2);
            allocation_records[counter].ptr = ptr2;
            allocation_records[counter].size = new_size;
            counter++;
        } else if (ptr2 == NULL && new_size != 0) {
            printf("Realloc: malloc(%d) failed; not enough memory.\n", (int)new_size);
        }
    } else {
        if (i == -1) {
            printf("Realloc: Unable to find %p in allocation records. Working with unknown pointer.\n", ptr);
        }
        //Realloc failed
        if (ptr2 == NULL) {
            if (new_size == 0) {
                printf("Realloc: Requested size 0; the original block %p has been freed.\n", ptr);
                // We have index of the original block
                if (i >= 0) {
                    allocation_records[i].ptr = NULL;
                    allocation_records[i].size = 0;
                }
            } else {
                printf("Realloc: Realloc of size %d returned NULL; not enough memory. Old memory block remains.\n", (int)new_size);
            }
        // Realloc succeeded
        } else {
            // We have info. about the old block
            if (i >= 0) {
                allocation_records[i].ptr = ptr2;
                allocation_records[i].size = new_size;
            // Old block has not been found
            } else if (counter < ARR_SIZE) {
                allocation_records[counter].ptr = ptr2;
                allocation_records[counter].size = new_size;
                counter++;
            }
        }
    }
    return ptr2;
}



int check_leaky_memory() {
    int leaky_count = 0;
    for (int i = 0; i < ARR_SIZE; i++) {
        AllocationRecord* a = &(allocation_records[i]);
        if (a->ptr != NULL) {
            printf("Leak at %p of size %d\n", a->ptr, (int)a->size);
            leaky_count++;
        }
    }
    return leaky_count;
}
void* MallocDebug_calloc(size_t num, size_t size) {
    void* p = original_calloc(num, size);
    if (p == NULL) {
        printf("Calloc: Failed to allocate memory of size %d\n", (int)(size * num));
        return p;
    }
    if (counter < ARR_SIZE) {
        allocation_records[counter].size = size*num;
        allocation_records[counter].ptr = p;
        counter++;
    }
    else {
        printf("Calloc: Maximum number of allocation records exceeded. Limited logging from now on...\n");
    }
    return p;
}
void MallocDebug_free(void* ptr) {
    int i = find_index(ptr);
    if (i == -1) {
        printf("Free: The pointer to the memory does not exist\n");
        original_free(ptr);
    }
    else if (i == -2) {
        printf("Free: Pointer to the unknown memory block\n");
        original_free(ptr);
    }
    else {
        original_free(allocation_records[i].ptr);
        allocation_records[i].ptr = NULL;
        allocation_records[i].size = NULL;
    }
   
}

int main()
{
    // we won't log this malloc therefore it will leak un-noticed
    void* ghost = malloc(1);
    initialise_allocation_records();
    // debug done before init
    MallocDebug_Done();
    // multiple inits
    MallocDebug_Init();
    MallocDebug_Init();
    ////MallocDebug_Init();
    void* test = malloc(100);
    void* test2 = malloc(0);
    void* b = calloc(10, 4);
    //free(test);
    //free(NULL);
    void* fail = malloc(100000000000000);
    void* r = realloc(b, 20);
    //free(b);
    void* r2 = realloc(r, 0);
    // These 2 will make program fail
    void* r3 = realloc(r2, 10); // should be equal to realloc(NULL, 10) because r2 is going to be null 
    void* test3 = realloc(NULL, 0);
    // multiple debug_done
    MallocDebug_Done();
    //MallocDebug_Done();
    return 0;
}



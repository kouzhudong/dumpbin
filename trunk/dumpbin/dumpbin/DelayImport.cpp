#include "pch.h"
#include "DelayImport.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void PrintOneDelayImport(_In_ PBYTE Data, _In_ DWORD Size, _In_ PIMAGE_DELAYLOAD_DESCRIPTOR DelayImportDirectory)
/*
这里的数据需进一步的解析。

*/
{
    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    printf("AllAttributes:%#010X.\r\n", DelayImportDirectory->Attributes.AllAttributes);

    PCHAR DllName = (PCHAR)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->DllNameRVA, NULL);
    printf("DllNameRVA:%#010X, %s.\r\n", DelayImportDirectory->DllNameRVA, DllName);

    //////////////////////////////////////////////////////////////////////////////////////////////

    HMODULE * ModuleHandle = (HMODULE *)ImageRvaToVa(NtHeaders,
                                                     Data,
                                                     DelayImportDirectory->ModuleHandleRVA,
                                                     NULL);
    //Data + DelayImportDirectory->ModuleHandleRVA,这个倒有内容。

    printf("ModuleHandleRVA:%#010X, %p.\r\n", DelayImportDirectory->ModuleHandleRVA, ModuleHandle);

    //////////////////////////////////////////////////////////////////////////////////////////////

    PIMAGE_THUNK_DATA ImportAddressTable = (PIMAGE_THUNK_DATA)
        ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->ImportAddressTableRVA, NULL);

    printf("ImportAddressTableRVA:%#010X, %p.\r\n", DelayImportDirectory->ImportAddressTableRVA, ImportAddressTable);

    if (IsPE32Ex(Data, Size)) {
        PIMAGE_THUNK_DATA64 ThunkData64 = (PIMAGE_THUNK_DATA64)ImportAddressTable;

        for (;; ThunkData64++) {
            ULONGLONG AddressOfData = ThunkData64->u1.AddressOfData;

            if (ThunkData64->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(AddressOfData)) {//AddressOfData > MAXLONG64
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL64(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)
                    ImageRvaToVa(NtHeaders, Data, (ULONG)AddressOfData & 0xffffffff, NULL);

                if (ImportByName) {
                    printf("\tHint:%#06X(%04d), ApiName:%s.\r\n",
                           ImportByName->Hint,
                           ImportByName->Hint,
                           ImportByName->Name);
                }
            }
        }
    } else {
        PIMAGE_THUNK_DATA32 ThunkData32 = (PIMAGE_THUNK_DATA32)ImportAddressTable;

        for (;; ThunkData32++) {
            DWORD AddressOfData = ThunkData32->u1.AddressOfData;

            if (ThunkData32->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(AddressOfData)) {//AddressOfData > MAXINT
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL32(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)
                    ImageRvaToVa(NtHeaders, Data, ThunkData32->u1.AddressOfData, NULL);

                if (ImportByName) {
                    printf("\tHint:%#06X(%04d), ApiName:%s.\r\n",
                           ImportByName->Hint,
                           ImportByName->Hint,
                           ImportByName->Name);
                }
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

    PIMAGE_IMPORT_BY_NAME ImportNameTable = (PIMAGE_IMPORT_BY_NAME)
        ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->ImportNameTableRVA, NULL);

    printf("ImportNameTableRVA:%#010X, %p.\r\n", DelayImportDirectory->ImportNameTableRVA, ImportNameTable);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //区分32和64.
    PIMAGE_THUNK_DATA BoundImportAddressTable = (PIMAGE_THUNK_DATA)
        ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->BoundImportAddressTableRVA, NULL);
    //Data + DelayImportDirectory->BoundImportAddressTableRVA,这个倒有内容。

    printf("BoundImportAddressTableRVA:%#010X, %p.\r\n",
           DelayImportDirectory->BoundImportAddressTableRVA,
           BoundImportAddressTable);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //区分32和64.
    PIMAGE_THUNK_DATA UnloadInformationTable = (PIMAGE_THUNK_DATA)
        ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->UnloadInformationTableRVA, NULL);

    printf("UnloadInformationTableRVA:%#010X, %p.\r\n",
           DelayImportDirectory->UnloadInformationTableRVA,
           UnloadInformationTable);

    //////////////////////////////////////////////////////////////////////////////////////////////

    CHAR TimeDateStamp[MAX_PATH] = {0};
    GetTimeDateStamp(DelayImportDirectory->TimeDateStamp, TimeDateStamp);
    printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n",
           DelayImportDirectory->TimeDateStamp,
           DelayImportDirectory->TimeDateStamp,
           TimeDateStamp);

    printf("\r\n");
}


DWORD DelayImport(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有DelayImport.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_DELAYLOAD_DESCRIPTOR DelayImportDirectory = (PIMAGE_DELAYLOAD_DESCRIPTOR)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//自己映射的用FALSE，操作系统加载的用TRUE。 
                                    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
                                    &size, &FoundHeader);

    printf("Delay Import Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    PIMAGE_DELAYLOAD_DESCRIPTOR temp = (PIMAGE_DELAYLOAD_DESCRIPTOR)DelayImportDirectory;

    //最后一个数据全为0.
    DWORD numbers = DataDirectory.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) - 1;

    for (DWORD len = 0; len < numbers; len++) {
        PrintOneDelayImport(Data, Size, temp);

        temp++;
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD DelayImport(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, DelayImport);
}

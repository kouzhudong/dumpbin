#include "pch.h"
#include "DelayImport.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void PrintOneDelayImport(_In_ PBYTE Data, _In_ DWORD Size, _In_ PIMAGE_DELAYLOAD_DESCRIPTOR DelayImportDirectory)
/*
这里的数据需进一步的解析。

*/
{
    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return;
    }

    printf("AllAttributes:%#010X.\r\n", DelayImportDirectory->Attributes.AllAttributes);

    PCHAR DllName = (PCHAR)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->DllNameRVA, NULL);
    printf("DllNameRVA:%#010X, %s.\r\n", DelayImportDirectory->DllNameRVA, DllName != NULL ? DllName : "(无效)");

    //////////////////////////////////////////////////////////////////////////////////////////////

    HMODULE * ModuleHandle = (HMODULE *)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->ModuleHandleRVA, NULL);
    //Data + DelayImportDirectory->ModuleHandleRVA,这个倒有内容。

    printf("ModuleHandleRVA:%#010X, %p.\r\n", DelayImportDirectory->ModuleHandleRVA, ModuleHandle);

    //////////////////////////////////////////////////////////////////////////////////////////////

    PIMAGE_THUNK_DATA ImportAddressTable = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->ImportAddressTableRVA, NULL);

    printf("ImportAddressTableRVA:%#010X, %p.\r\n", DelayImportDirectory->ImportAddressTableRVA, ImportAddressTable);

    // 名称表才是存放 Hint/Name 的地方；有的文件把它置 0，此时加载前的 IAT 和它内容一致。
    PIMAGE_THUNK_DATA DelayNameTable = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->ImportNameTableRVA, NULL);
    printf("ImportNameTableRVA:%#010X, %p.\r\n", DelayImportDirectory->ImportNameTableRVA, DelayNameTable);

    if (DelayNameTable == NULL) {
        DelayNameTable = ImportAddressTable;
    }

    if (DelayNameTable == NULL) {
        LOGA(WARNING_LEVEL, "延迟导入名称表地址无效");
        printf("\r\n");
        return;
    }

    if (IsPE32Ex(Data, Size)) {
        PIMAGE_THUNK_DATA64 ThunkData64 = (PIMAGE_THUNK_DATA64)DelayNameTable;

        for (;; ThunkData64++) {
            ULONGLONG AddressOfData = ThunkData64->u1.AddressOfData;

            if (ThunkData64->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(AddressOfData)) {//AddressOfData > MAXLONG64
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL64(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(NtHeaders, Data, (ULONG)AddressOfData, NULL);
                if (ImportByName) {
                    printf("\tHint:%#06X(%04d), ApiName:%s.\r\n", ImportByName->Hint, ImportByName->Hint, ImportByName->Name);
                }
            }
        }
    } else {
        PIMAGE_THUNK_DATA32 ThunkData32 = (PIMAGE_THUNK_DATA32)DelayNameTable;

        for (;; ThunkData32++) {
            DWORD AddressOfData = ThunkData32->u1.AddressOfData;

            if (ThunkData32->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(AddressOfData)) {//AddressOfData > MAXINT
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL32(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(NtHeaders, Data, ThunkData32->u1.AddressOfData, NULL);
                if (ImportByName) {
                    printf("\tHint:%#06X(%04d), ApiName:%s.\r\n", ImportByName->Hint, ImportByName->Hint, ImportByName->Name);
                }
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

    //区分32和64.
    PIMAGE_THUNK_DATA BoundImportAddressTable = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->BoundImportAddressTableRVA, NULL);
    //Data + DelayImportDirectory->BoundImportAddressTableRVA,这个倒有内容。

    printf("BoundImportAddressTableRVA:%#010X, %p.\r\n", DelayImportDirectory->BoundImportAddressTableRVA, BoundImportAddressTable);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //区分32和64.
    PIMAGE_THUNK_DATA UnloadInformationTable = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, DelayImportDirectory->UnloadInformationTableRVA, NULL);

    printf("UnloadInformationTableRVA:%#010X, %p.\r\n", DelayImportDirectory->UnloadInformationTableRVA, UnloadInformationTable);

    //////////////////////////////////////////////////////////////////////////////////////////////

    CHAR TimeDateStamp[MAX_PATH] = {0};
    GetTimeDateStamp(DelayImportDirectory->TimeDateStamp, TimeDateStamp);
    printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", DelayImportDirectory->TimeDateStamp, DelayImportDirectory->TimeDateStamp, TimeDateStamp);

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
        ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &size, &FoundHeader);
    if (DelayImportDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("Delay Import Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    /*
    描述符数组以全 0 项结束。原来的写法 Size/sizeof-1 在 Size 小于一个描述符时会下溢，
    这里改成"全 0 结束 + Size 上界"(Size 为 0 时只靠结束项)。
    */
    DWORD maxCount = (size >= sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)) ? (size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)) : 0;

    for (DWORD i = 0; maxCount == 0 || i < maxCount; i++, DelayImportDirectory++) {
        if (DelayImportDirectory->Attributes.AllAttributes == 0 &&
            DelayImportDirectory->DllNameRVA == 0 &&
            DelayImportDirectory->ModuleHandleRVA == 0 &&
            DelayImportDirectory->ImportAddressTableRVA == 0 &&
            DelayImportDirectory->ImportNameTableRVA == 0 &&
            DelayImportDirectory->BoundImportAddressTableRVA == 0 &&
            DelayImportDirectory->UnloadInformationTableRVA == 0 &&
            DelayImportDirectory->TimeDateStamp == 0) {
            break;
        }

        printf("index:%06u.\r\n", i);
        PrintOneDelayImport(Data, Size, DelayImportDirectory);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD DelayImport(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, DelayImport);
}

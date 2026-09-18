#include "pch.h"
#include "Import.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void PrintImport(_In_ PBYTE Data, _In_ DWORD Size, _In_ PIMAGE_IMPORT_DESCRIPTOR ImportDirectory)
{
    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return;
    }

    printf("OriginalFirstThunk:%#010X.\r\n", ImportDirectory->OriginalFirstThunk);
    printf("TimeDateStamp:%#010X.\r\n", ImportDirectory->TimeDateStamp);
    printf("ForwarderChain:%#010X.\r\n", ImportDirectory->ForwarderChain);
    printf("Name:%#010X.\r\n", ImportDirectory->Name);
    printf("FirstThunk:%#010X.\r\n", ImportDirectory->FirstThunk);

    PCHAR DllName = (PCHAR)ImageRvaToVa(NtHeaders, Data, (ULONG)ImportDirectory->Name, NULL);
    printf("DllName:%s.\r\n", DllName != NULL ? DllName : "(无效)");

    PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, ImportDirectory->OriginalFirstThunk, NULL);
    if (ThunkData == NULL) {
        //有的链接器把 OriginalFirstThunk 置 0，此时 IAT(加载前)本身就是名称表。
        ThunkData = (PIMAGE_THUNK_DATA)ImageRvaToVa(NtHeaders, Data, ImportDirectory->FirstThunk, NULL);
    }

    if (ThunkData == NULL) {
        LOGA(WARNING_LEVEL, "导入名称表地址无效");
        printf("\r\n");
        return;
    }

    if (IsPE32Ex(Data, Size)) {
        PIMAGE_THUNK_DATA64 ThunkData64 = (PIMAGE_THUNK_DATA64)ThunkData;

        for (;; ThunkData64++) {
            ULONGLONG AddressOfData = ThunkData64->u1.AddressOfData;

            if (ThunkData64->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(AddressOfData)) {//AddressOfData > MAXLONG64
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL64(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(NtHeaders, Data, (ULONG)AddressOfData & 0xffffffff, NULL);
                if (ImportByName == NULL) {
                    LOGA(WARNING_LEVEL, "导入名称地址无效:%#010llX", AddressOfData);
                    break;
                }

                printf("\tHint:%#06X(%04d), ApiName:%s.\r\n", ImportByName->Hint, ImportByName->Hint, ImportByName->Name);
            }
        }
    } else {
        PIMAGE_THUNK_DATA32 ThunkData32 = (PIMAGE_THUNK_DATA32)ThunkData;

        for (;; ThunkData32++) {
            DWORD AddressOfData = ThunkData32->u1.AddressOfData;

            if (ThunkData32->u1.AddressOfData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(AddressOfData)) {//AddressOfData > MAXINT
                printf("\tOrdinal:%d.\r\n", (WORD)IMAGE_ORDINAL32(AddressOfData));
            } else {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(NtHeaders, Data, ThunkData32->u1.AddressOfData, NULL);
                if (ImportByName == NULL) {
                    LOGA(WARNING_LEVEL, "导入名称地址无效:%#010X", AddressOfData);
                    break;
                }

                printf("\tHint:%#06X(%04d), ApiName:%s.\r\n", ImportByName->Hint, ImportByName->Hint, ImportByName->Name);
            }
        }
    }

    printf("\r\n");
}


DWORD Import(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_IMPORT, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Import.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &FoundHeader);
    if (ImportDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("Import Directory Information:\r\n");

    /*
    描述符数组以全 0 项结束。数据目录的 Size 可能包含结束项也可能不包含，所以按 Size 算出的
    个数只是上界；Size 为 0 时(有些文件如此)只能靠结束项，由 MapFile 的 SEH 兜底。
    */
    DWORD maxCount = (size >= sizeof(IMAGE_IMPORT_DESCRIPTOR)) ? (size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) : 0;

    for (DWORD i = 0; maxCount == 0 || i < maxCount; i++, ImportDirectory++) {
        if (ImportDirectory->OriginalFirstThunk == 0 &&
            ImportDirectory->TimeDateStamp == NULL &&
            ImportDirectory->ForwarderChain == NULL &&
            ImportDirectory->Name == NULL &&
            ImportDirectory->FirstThunk == NULL) {
            break;
        }

        PrintImport(Data, Size, ImportDirectory);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Import(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Import);
}

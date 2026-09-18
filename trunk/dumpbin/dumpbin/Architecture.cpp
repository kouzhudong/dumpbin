#include "pch.h"
#include "Architecture.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Architecture(_In_ PBYTE Data, _In_ DWORD Size)
/*
参考：\win2k\trunk\private\ntos\dll\ldrsnap.c的AlphaFindArchitectureFixups。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Architecture.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_ARCHITECTURE_HEADER ArchitectureDirectory = (PIMAGE_ARCHITECTURE_HEADER)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//映射（MapViewOfFile）的用FALSE，原始读取(如：ReadFile)的用TRUE。
                                    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
                                    &size, &FoundHeader);
    if (ArchitectureDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    printf("Architecture Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);

    //每个 IMAGE_ARCHITECTURE_HEADER 指向一组 IMAGE_ARCHITECTURE_ENTRY，最后以 0xFFFFFFFF 结束。
    DWORD count = DataDirectory.Size / sizeof(IMAGE_ARCHITECTURE_HEADER);
    printf("Architecture Header Numbers:%u.\r\n", count);
    printf("\r\n");

    for (DWORD i = 0; i < count; i++) {
        PIMAGE_ARCHITECTURE_HEADER Entry = &ArchitectureDirectory[i];

        printf("index:%06u, AmaskValue:%u, AmaskShift:%u, FirstEntryRVA:%#010X.\r\n",
               i, Entry->AmaskValue, Entry->AmaskShift, Entry->FirstEntryRVA);

        PIMAGE_ARCHITECTURE_ENTRY FixupEntry = (PIMAGE_ARCHITECTURE_ENTRY)ImageRvaToVa(NtHeaders, Data, Entry->FirstEntryRVA, NULL);
        if (FixupEntry == NULL) {
            printf("\tFixupEntry 无效(RVA:%#010X).\r\n", Entry->FirstEntryRVA);
            continue;
        }

        // 数组中间可能有填 0 的四字，要跳过；0xFFFFFFFF 才是结束标记。上限用于兜底畸形数据。
        for (DWORD j = 0; j < 0x10000; j++, FixupEntry++) {
            if (FixupEntry->FixupInstRVA == 0xFFFFFFFF && FixupEntry->NewInst == 0xFFFFFFFF) {
                break;
            }

            printf("\tindex:%06u, FixupInstRVA:%#010X, NewInst:%#010X.\r\n", j, FixupEntry->FixupInstRVA, FixupEntry->NewInst);
        }
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Architecture(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Architecture);
}

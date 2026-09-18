#include "pch.h"
#include "BaseReloc.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


PCSTR GetBaseRelocType(_In_ WORD Type)
{
    PCSTR TypeString = NULL;

    switch (Type) {
    case IMAGE_REL_BASED_ABSOLUTE:
        TypeString = "ABSOLUTE";
        break;
    case IMAGE_REL_BASED_HIGH:
        TypeString = "HIGH";
        break;
    case IMAGE_REL_BASED_LOW:
        TypeString = "LOW";
        break;
    case IMAGE_REL_BASED_HIGHLOW:
        TypeString = "HIGHLOW";
        break;
    case IMAGE_REL_BASED_HIGHADJ:
        TypeString = "HIGHADJ";
        break;
    case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
        TypeString = "MACHINE_SPECIFIC_5";
        break;
    case IMAGE_REL_BASED_RESERVED:
        TypeString = "RESERVED";
        break;
    case IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
        TypeString = "MACHINE_SPECIFIC_7";
        break;
    case IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
        TypeString = "MACHINE_SPECIFIC_8";
        break;
    case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
        TypeString = "MACHINE_SPECIFIC_9";
        break;
    case IMAGE_REL_BASED_DIR64:
        TypeString = "DIR64";
        break;    
    default:
        LOGA(ERROR_LEVEL, "Type:%#X", Type);
        TypeString = "未定义";
        break;
    }

    return TypeString;
}


DWORD BaseReloc(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_BASERELOC, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress || 0 == DataDirectory.Size) {
        printf("此文件没有BaseReloc.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_BASE_RELOCATION BaseRelocDirectory = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size, &FoundHeader);
    if (BaseRelocDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("BaseReloc Directory Information:\r\n");
    if (FoundHeader) {
        CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        GetSectionName(FoundHeader, SectionName);
        printf("SectionName:%s.\r\n", SectionName);
    }

    // 数据目录里的 Size 未必和实际块的总长一致，取小的那个作为遍历上界。
    DWORD total = (size != 0 && size < DataDirectory.Size) ? size : DataDirectory.Size;

    //可以给下面的信息加上索引序号。

    for (DWORD offset = 0; offset + sizeof(IMAGE_BASE_RELOCATION) <= total; ) {
        PIMAGE_BASE_RELOCATION temp = (PIMAGE_BASE_RELOCATION)((PBYTE)BaseRelocDirectory + offset);

        // SizeOfBlock 是块(含头)的总长，必须容得下块头且不越过上界，否则解析会越界或死循环。
        if (temp->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            temp->SizeOfBlock > total - offset) {
            LOGA(ERROR_LEVEL, "SizeOfBlock 非法:%#X, 偏移:%#X", temp->SizeOfBlock, offset);
            break;
        }

        printf("VirtualAddress:%#010X, SizeOfBlock:%#010X.\r\n", temp->VirtualAddress, temp->SizeOfBlock);

        DWORD SizeOfBlock = temp->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
        SizeOfBlock /= sizeof(BaseRelocBit);

        PBaseRelocBit BaseRelocBit = (PBaseRelocBit)((PBYTE)temp + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < SizeOfBlock; i++) {
            printf("\tType:%#06X, %s, Offset:%#06X.\r\n",
                   BaseRelocBit->Type,
                   GetBaseRelocType(BaseRelocBit->Type), //经测试，这个值都在合理的范围内，说明这个解析不错。
                   BaseRelocBit->Offset);

            BaseRelocBit++;
        }

        offset += temp->SizeOfBlock;
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD BaseReloc(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, BaseReloc);
}

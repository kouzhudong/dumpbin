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

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有BaseReloc.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_BASE_RELOCATION BaseRelocDirectory = (PIMAGE_BASE_RELOCATION)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//映射（MapViewOfFile）的用FALSE，原始读取(如：ReadFile)的用TRUE。 
                                    IMAGE_DIRECTORY_ENTRY_BASERELOC,
                                    &size, &FoundHeader);

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    printf("BaseReloc Directory Information:\r\n");   

    PIMAGE_BASE_RELOCATION temp = (PIMAGE_BASE_RELOCATION)BaseRelocDirectory;

    //可以给下面的信息加上索引序号。

    for (DWORD Len = 0; Len < DataDirectory.Size; Len += temp->SizeOfBlock) {

        printf("VirtualAddress:%#010X, SizeOfBlock:%#010X.\r\n", temp->VirtualAddress, temp->SizeOfBlock);

        DWORD SizeOfBlock = temp->SizeOfBlock - sizeof(temp->SizeOfBlock) - sizeof(temp->SizeOfBlock);
        SizeOfBlock /= sizeof(DWORD);

        PBaseRelocBit BaseRelocBit = (PBaseRelocBit)((PBYTE)temp + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < SizeOfBlock; i++) {
            printf("\tType:%#06X, %s, Offset:%#06X.\r\n", 
                   BaseRelocBit->Type, 
                   GetBaseRelocType(BaseRelocBit->Type), //经测试，这个值都在合理的范围内，说明这个解析不错。
                   BaseRelocBit->Offset);
  
            BaseRelocBit++;
        }
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD BaseReloc(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, BaseReloc);
}

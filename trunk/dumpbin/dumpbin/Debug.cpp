#include "pch.h"
#include "Debug.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


PCSTR GetDebugType(_In_ DWORD Type)
{
    PCSTR TypeString = NULL;

    switch (Type) {
    case IMAGE_DEBUG_TYPE_UNKNOWN:
        TypeString = "UNKNOWN";
        break;
    case IMAGE_DEBUG_TYPE_COFF:
        TypeString = "COFF";
        break;
    case IMAGE_DEBUG_TYPE_CODEVIEW:
        TypeString = "CODEVIEW";
        break;
    case IMAGE_DEBUG_TYPE_FPO:
        TypeString = "FPO";
        break;
    case IMAGE_DEBUG_TYPE_MISC:
        TypeString = "MISC";
        break;
    case IMAGE_DEBUG_TYPE_EXCEPTION:
        TypeString = "EXCEPTION";
        break;
    case IMAGE_DEBUG_TYPE_FIXUP:
        TypeString = "FIXUP";
        break;
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
        TypeString = "OMAP_TO_SRC";
        break;
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
        TypeString = "OMAP_FROM_SRC";
        break;
    case IMAGE_DEBUG_TYPE_BORLAND:
        TypeString = "BORLAND";
        break;
    case IMAGE_DEBUG_TYPE_RESERVED10:
        TypeString = "RESERVED10";
        break;
    case IMAGE_DEBUG_TYPE_CLSID:
        TypeString = "CLSID";
        break;
    case IMAGE_DEBUG_TYPE_VC_FEATURE:
        TypeString = "VC_FEATURE";
        break;
    case IMAGE_DEBUG_TYPE_POGO:
        TypeString = "POGO";
        break;
    case IMAGE_DEBUG_TYPE_ILTCG:
        TypeString = "ILTCG";
        break;
    case IMAGE_DEBUG_TYPE_MPX:
        TypeString = "MPX";
        break;
    case IMAGE_DEBUG_TYPE_REPRO:
        TypeString = "REPRO";
        break;
    case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
        TypeString = "EX_DLLCHARACTERISTICS";
        break;
    default:
        LOGA(ERROR_LEVEL, "Type:%#X", Type);
        TypeString = "未定义";
        break;
    }

    return TypeString;
}


static bool IsDebugRawDataInFile(_In_ PIMAGE_DEBUG_DIRECTORY DebugDirectory, _In_ DWORD Size)
/*
PointerToRawData 是文件偏移，数据必须整个落在文件里才能按结构体去读。
*/
{
    return DebugDirectory->PointerToRawData != 0 &&
           DebugDirectory->PointerToRawData <= Size &&
           DebugDirectory->SizeOfData <= Size - DebugDirectory->PointerToRawData;
}


void PrintDebug(_In_ PBYTE Data, _In_ DWORD Size, _In_ PIMAGE_DEBUG_DIRECTORY DebugDirectory)
{
    printf("Characteristics:%#010X.\r\n", DebugDirectory->Characteristics);//保留，必须为 0。

    CHAR TimeDateStamp[MAX_PATH] = {0};
    GetTimeDateStamp(DebugDirectory->TimeDateStamp, TimeDateStamp);
    printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", DebugDirectory->TimeDateStamp, DebugDirectory->TimeDateStamp, TimeDateStamp);

    printf("Version:%d.%d.\r\n", DebugDirectory->MajorVersion, DebugDirectory->MinorVersion);

    printf("Type:%#010X, %s.\r\n", DebugDirectory->Type, GetDebugType(DebugDirectory->Type));

    printf("SizeOfData:%#010X.\r\n", DebugDirectory->SizeOfData);
    printf("AddressOfRawData:%#010X.\r\n", DebugDirectory->AddressOfRawData);//RVA，需进一步的解析。
    printf("PointerToRawData:%#010X.\r\n", DebugDirectory->PointerToRawData);//文件偏移，读数据要用这个。

    switch (DebugDirectory->Type) {
    case IMAGE_DEBUG_TYPE_UNKNOWN:

        break;
    case IMAGE_DEBUG_TYPE_COFF:
    {
        //官方定义的数据结构是PIMAGE_COFF_SYMBOLS_HEADER
        if (!IsDebugRawDataInFile(DebugDirectory, Size)) {
            LOGA(WARNING_LEVEL, "IMAGE_DEBUG_TYPE_COFF 数据越界");
            break;
        }

        PIMAGE_COFF_SYMBOLS_HEADER CoffSymbolsHeader = (PIMAGE_COFF_SYMBOLS_HEADER)(Data + DebugDirectory->PointerToRawData);

        printf("NumberOfSymbols:%#010X.\r\n", CoffSymbolsHeader->NumberOfSymbols);
        printf("LvaToFirstSymbol:%#010X.\r\n", CoffSymbolsHeader->LvaToFirstSymbol);
        printf("NumberOfLinenumbers:%#010X.\r\n", CoffSymbolsHeader->NumberOfLinenumbers);
        printf("LvaToFirstLinenumber:%#010X.\r\n", CoffSymbolsHeader->LvaToFirstLinenumber);
        printf("RvaToFirstByteOfCode:%#010X.\r\n", CoffSymbolsHeader->RvaToFirstByteOfCode);
        printf("RvaToLastByteOfCode:%#010X.\r\n", CoffSymbolsHeader->RvaToLastByteOfCode);
        printf("RvaToFirstByteOfData:%#010X.\r\n", CoffSymbolsHeader->RvaToFirstByteOfData);
        printf("RvaToLastByteOfData:%#010X.\r\n", CoffSymbolsHeader->RvaToLastByteOfData);

        break;
    }
    case IMAGE_DEBUG_TYPE_CODEVIEW:
    {
        if (!IsDebugRawDataInFile(DebugDirectory, Size) ||
            DebugDirectory->SizeOfData <= offsetof(CV_INFO_PDB70, PdbFileName)) {
            LOGA(WARNING_LEVEL, "IMAGE_DEBUG_TYPE_CODEVIEW 数据越界或过短");
            break;
        }

        CV_INFO_PDB70 * Info = (CV_INFO_PDB70 *)(Data + DebugDirectory->PointerToRawData);

        //PdbFileName 是变长字符串，长度由 SizeOfData 限定，未必以 0 结尾，先拷出来再转换。
        SIZE_T cchMax = DebugDirectory->SizeOfData - offsetof(CV_INFO_PDB70, PdbFileName);
        CHAR * PdbFileName = (CHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchMax + 1);
        if (PdbFileName != NULL) {
            RtlCopyMemory(PdbFileName, Info->PdbFileName, cchMax);

            LPWSTR PdbFileNameW = UTF8ToWide(PdbFileName);
            if (PdbFileNameW != NULL) {
                printf("PdbFileName:%ls.\r\n", PdbFileNameW);
                HeapFree(GetProcessHeap(), 0, PdbFileNameW);
            }

            HeapFree(GetProcessHeap(), 0, PdbFileName);
        }

        break;
    }
    case IMAGE_DEBUG_TYPE_FPO:
    {
        //官方定义的数据结构是PFPO_DATA
        if (!IsDebugRawDataInFile(DebugDirectory, Size) ||
            DebugDirectory->SizeOfData < sizeof(FPO_DATA)) {
            LOGA(WARNING_LEVEL, "IMAGE_DEBUG_TYPE_FPO 数据越界或过短");
            break;
        }

        PFPO_DATA fpo = (PFPO_DATA)(Data + DebugDirectory->PointerToRawData);

        printf("ulOffStart:%#010X.\r\n", fpo->ulOffStart);
        printf("cbProcSize:%#010X.\r\n", fpo->cbProcSize);
        printf("cdwLocals:%#010X.\r\n", fpo->cdwLocals);

        printf("cdwParams:%#06X.\r\n", fpo->cdwParams);

        printf("cbProlog:%#06X.\r\n", fpo->cbProlog);
        printf("cbRegs:%#06X.\r\n", fpo->cbRegs);
        printf("fHasSEH:%#06X.\r\n", fpo->fHasSEH);
        printf("fUseBP:%#06X.\r\n", fpo->fUseBP);
        printf("reserved:%#06X.\r\n", fpo->reserved);
        printf("cbFrame:%#06X.\r\n", fpo->cbFrame);

        break;
    }
    case IMAGE_DEBUG_TYPE_MISC:
    {
        //官方定义的数据结构是PIMAGE_DEBUG_MISC
        if (!IsDebugRawDataInFile(DebugDirectory, Size) ||
            DebugDirectory->SizeOfData < sizeof(IMAGE_DEBUG_MISC)) {
            LOGA(WARNING_LEVEL, "IMAGE_DEBUG_TYPE_MISC 数据越界或过短");
            break;
        }

        PIMAGE_DEBUG_MISC misc = (PIMAGE_DEBUG_MISC)(Data + DebugDirectory->PointerToRawData);

        printf("DataType:%#010X.\r\n", misc->DataType);
        printf("Length:%#010X.\r\n", misc->Length);

        printf("Length:%d.\r\n", misc->Unicode);

        printf("Reserved[3]:%#04X%#04X%#04X.\r\n", misc->Reserved[0], misc->Reserved[1], misc->Reserved[2]);

        printf("Data[1]:%#04X.\r\n", misc->Data[0]);//这个的数据应该有个长度指示。

        break;
    }
    case IMAGE_DEBUG_TYPE_EXCEPTION:

        break;
    case IMAGE_DEBUG_TYPE_FIXUP:

        break;
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:

        break;
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:

        break;
    case IMAGE_DEBUG_TYPE_BORLAND:

        break;
    case IMAGE_DEBUG_TYPE_RESERVED10:

        break;
    case IMAGE_DEBUG_TYPE_CLSID:

        break;
    case IMAGE_DEBUG_TYPE_VC_FEATURE:
    {
        /*
        * 微软的dumpbin显示的如下：
            5F685417 feat          14 0013C000    E4200    Counts: Pre-VC++ 11.00=0, C/C++=252, /GS=252, /sdl=19, guardN=233

        * 数据在 PointerToRawData 处(AddressOfRawData 是 RVA)，格式未公开，暂不解析。
        */
        break;
    }
    case IMAGE_DEBUG_TYPE_POGO:
    {
        /*
        微软的dumpbin显示：A371A2E9 coffgrp     1500 000401E8    3F9E8    50475500 (PGU)
        没有找到相关的数据结构。

        请看官仔细观察下面的几个地址的里的数据，找出数据格式或数据定义。
        */
        break;
    }
    case IMAGE_DEBUG_TYPE_ILTCG:

        break;
    case IMAGE_DEBUG_TYPE_MPX:

        break;
    case IMAGE_DEBUG_TYPE_REPRO:
    {
        /*
        微软的dumpbin显示：
        A371A2E9 repro         24 00041710    40F10    C5 55 1F 64 20 92 CC 1D 4F 59 FA CC 72 EA 54 DA 1A 20 04 75 03 C7 0A E4 CC 5C 9A BB E9 A2 71 A3
        没有找到相关的数据结构。

        请看官仔细观察下面的几个地址的里的数据，找出数据格式或数据定义。

        PointerToRawData 处的数据如下：
        0x02DE0F10  20 00 00 00 c5 55 1f 64 20 92 cc 1d 4f 59 fa cc   ...?U.d ??.OY??
        0x02DE0F20  72 ea 54 da 1a 20 04 75 03 c7 0a e4 cc 5c 9a bb  r?T?. .u.?.??\??
        0x02DE0F30  e9 a2 71 a3 00 00 00 00
        可以看到前面的0x20是长度。
        */
        break;
    }
    case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:

        break;
    default:
        LOGA(WARNING_LEVEL, "未定义的Debug Type:%#X", DebugDirectory->Type);
        break;
    }

    printf("\r\n");
}


DWORD Debug(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_DEBUG, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Debug.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_DEBUG_DIRECTORY DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_DEBUG, &size, &FoundHeader);
    if (DebugDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("Debug Directory Information:\r\n");

    // 数据目录里的 Size 未必和实际长度一致，取小的那个作为遍历上界。
    DWORD total = (size != 0 && size < DataDirectory.Size) ? size : DataDirectory.Size;

    for (DWORD i = 0; i * sizeof(IMAGE_DEBUG_DIRECTORY) < total; i++, DebugDirectory++) {
        printf("index:%06u.\r\n", i);

        PrintDebug(Data, Size, DebugDirectory);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Debug(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Debug);
}

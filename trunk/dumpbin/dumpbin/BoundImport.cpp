#include "pch.h"
#include "BoundImport.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void PrintBoundImportName(_In_ PBYTE TableBase, _In_ DWORD TableBytes, _In_ DWORD OffsetModuleName)
/*
OffsetModuleName 是相对绑定导入表起始处的偏移，指向模块名字符串。
*/
{
    if (OffsetModuleName == 0 || OffsetModuleName >= TableBytes) {
        printf("(无效偏移:%#X)", OffsetModuleName);
        return;
    }

    //用精度限制长度，畸形数据也不会读越界。
    printf("%.*s", (int)(TableBytes - OffsetModuleName), (PCSTR)TableBase + OffsetModuleName);
}


DWORD BoundImport(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有BoundImport.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundImportDirectory = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)
        ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &size, &FoundHeader);
    if (BoundImportDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("BoundImport Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    /*
    绑定导入表由若干个 IMAGE_BOUND_IMPORT_DESCRIPTOR 组成，最后以全 0 项结束；
    每个描述符后面紧跟它自己声明的 NumberOfModuleForwarderRefs 个 IMAGE_BOUND_FORWARDER_REF。
    */
    PBYTE TableBase = (PBYTE)BoundImportDirectory;

    //表的可读范围：数据目录声明的长度，为 0 时退回到文件剩余长度。
    DWORD table_bytes = (size != 0 && size <= Size) ? size : (Size - (DWORD)(TableBase - Data));

    DWORD index = 0;
    for (DWORD walked = 0; walked + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= table_bytes; ) {
        PIMAGE_BOUND_IMPORT_DESCRIPTOR Descriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(TableBase + walked);

        if (Descriptor->TimeDateStamp == 0 &&
            Descriptor->OffsetModuleName == 0 &&
            Descriptor->NumberOfModuleForwarderRefs == 0) {
            break;//全 0 项是结束标记。
        }

        printf("index:%u.\r\n", index++);

        CHAR TimeDateStamp[MAX_PATH] = {0};
        GetTimeDateStamp(Descriptor->TimeDateStamp, TimeDateStamp);
        printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", Descriptor->TimeDateStamp, Descriptor->TimeDateStamp, TimeDateStamp);

        printf("OffsetModuleName:%#06X, 模块名：", Descriptor->OffsetModuleName);
        PrintBoundImportName(TableBase, table_bytes, Descriptor->OffsetModuleName);
        printf(".\r\n");

        DWORD refs_bytes = (DWORD)Descriptor->NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF);
        if (walked + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + refs_bytes > table_bytes) {
            LOGA(WARNING_LEVEL, "转发引用越界, 个数:%u", Descriptor->NumberOfModuleForwarderRefs);
            break;
        }

        for (WORD i = 0; i < Descriptor->NumberOfModuleForwarderRefs; i++) {
            PIMAGE_BOUND_FORWARDER_REF BoundForwarderRef = (PIMAGE_BOUND_FORWARDER_REF)(TableBase + walked + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + i * sizeof(IMAGE_BOUND_FORWARDER_REF));

            CHAR ForwarderTimeDateStamp[MAX_PATH] = {0};
            GetTimeDateStamp(BoundForwarderRef->TimeDateStamp, ForwarderTimeDateStamp);
            printf("\tTimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", BoundForwarderRef->TimeDateStamp, BoundForwarderRef->TimeDateStamp, ForwarderTimeDateStamp);

            printf("\tOffsetModuleName:%#06X, 模块名：", BoundForwarderRef->OffsetModuleName);
            PrintBoundImportName(TableBase, table_bytes, BoundForwarderRef->OffsetModuleName);
            printf(".\r\n");

            printf("\tReserved:%#06X.\r\n", BoundForwarderRef->Reserved);

            printf("\r\n");
        }

        walked += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + refs_bytes;
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD BoundImport(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, BoundImport);
}

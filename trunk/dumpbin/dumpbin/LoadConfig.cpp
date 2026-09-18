#include "pch.h"
#include "LoadConfig.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
LoadConfigDirectory->Size 说明该结构在文件里实际有多少字节。老文件的结构可能比当前 SDK 的短，
超出部分不存在，不能按结构体偏移去读，所以逐域判断后再打印。
*/
#define LC_FIELD_PRESENT(Type, dir, AvailableSize, field) \
    (offsetof(Type, field) + sizeof((dir)->field) <= (AvailableSize))

#define PRINT_LC_FIELD(Type, dir, AvailableSize, field, format) \
    do { \
        if (LC_FIELD_PRESENT(Type, dir, AvailableSize, field)) { \
            printf(#field ":" format ".\r\n", (dir)->field); \
        } \
    } while (0)

#define PRINT_LC_SUBFIELD(Type, dir, AvailableSize, sub, field, format) \
    do { \
        if (offsetof(Type, sub) + sizeof((dir)->sub.field) <= (AvailableSize)) { \
            printf(#sub "." #field ":" format ".\r\n", (dir)->sub.field); \
        } \
    } while (0)


void PrintLoadConfig64(_In_ PIMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfigDirectory64, _In_ DWORD AvailableSize)
{
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, Size, "%#010X");

    if (LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, TimeDateStamp)) {
        CHAR TimeDateStamp[MAX_PATH] = {0};
        GetTimeDateStamp(LoadConfigDirectory64->TimeDateStamp, TimeDateStamp);
        printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", LoadConfigDirectory64->TimeDateStamp, LoadConfigDirectory64->TimeDateStamp, TimeDateStamp);
    }

    if (LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, MajorVersion) &&
        LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, MinorVersion)) {
        printf("Version:%d.%d.\r\n", LoadConfigDirectory64->MajorVersion, LoadConfigDirectory64->MinorVersion);
    }

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GlobalFlagsClear, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GlobalFlagsSet, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CriticalSectionDefaultTimeout, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DeCommitFreeBlockThreshold, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DeCommitTotalFreeThreshold, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, LockPrefixTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, MaximumAllocationSize, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, VirtualMemoryThreshold, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, ProcessAffinityMask, "%#016llX");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, ProcessHeapFlags, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CSDVersion, "%#06X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DependentLoadFlags, "%#06X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, EditList, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, SecurityCookie, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, SEHandlerTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, SEHandlerCount, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardCFCheckFunctionPointer, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardCFDispatchFunctionPointer, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardCFFunctionTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardCFFunctionCount, "%#016llX");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardFlags, "%#010X");

    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CodeIntegrity, Flags, "%#06X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CodeIntegrity, Catalog, "%#06X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CodeIntegrity, CatalogOffset, "%#010X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CodeIntegrity, Reserved, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardAddressTakenIatEntryTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardAddressTakenIatEntryCount, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardLongJumpTargetTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardLongJumpTargetCount, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DynamicValueRelocTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, CHPEMetadataPointer, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardRFFailureRoutine, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardRFFailureRoutineFunctionPointer, "%#016llX");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DynamicValueRelocTableOffset, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, DynamicValueRelocTableSection, "%#06X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, Reserved2, "%#06X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardRFVerifyStackPointerFunctionPointer, "%#016llX");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, HotPatchTableOffset, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, Reserved3, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, EnclaveConfigurationPointer, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, VolatileMetadataPointer, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardEHContinuationTable, "%#016llX");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, LoadConfigDirectory64, AvailableSize, GuardEHContinuationCount, "%#016llX");
}


void PrintLoadConfig32(_In_ PIMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfigDirectory32, _In_ DWORD AvailableSize)
{
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, Size, "%#010X");

    if (LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, TimeDateStamp)) {
        CHAR TimeDateStamp[MAX_PATH] = {0};
        GetTimeDateStamp(LoadConfigDirectory32->TimeDateStamp, TimeDateStamp);
        printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", LoadConfigDirectory32->TimeDateStamp, LoadConfigDirectory32->TimeDateStamp, TimeDateStamp);
    }

    if (LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, MajorVersion) &&
        LC_FIELD_PRESENT(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, MinorVersion)) {
        printf("Version:%d.%d.\r\n", LoadConfigDirectory32->MajorVersion, LoadConfigDirectory32->MinorVersion);
    }

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GlobalFlagsClear, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GlobalFlagsSet, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CriticalSectionDefaultTimeout, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DeCommitFreeBlockThreshold, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DeCommitTotalFreeThreshold, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, LockPrefixTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, MaximumAllocationSize, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, VirtualMemoryThreshold, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, ProcessHeapFlags, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, ProcessAffinityMask, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CSDVersion, "%#06X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DependentLoadFlags, "%#06X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, EditList, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, SecurityCookie, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, SEHandlerTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, SEHandlerCount, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardCFCheckFunctionPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardCFDispatchFunctionPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardCFFunctionTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardCFFunctionCount, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardFlags, "%#010X");

    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CodeIntegrity, Flags, "%#06X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CodeIntegrity, Catalog, "%#06X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CodeIntegrity, CatalogOffset, "%#010X");
    PRINT_LC_SUBFIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CodeIntegrity, Reserved, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardAddressTakenIatEntryTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardAddressTakenIatEntryCount, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardLongJumpTargetTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardLongJumpTargetCount, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DynamicValueRelocTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, CHPEMetadataPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardRFFailureRoutine, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardRFFailureRoutineFunctionPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DynamicValueRelocTableOffset, "%#010X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, DynamicValueRelocTableSection, "%#06X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, Reserved2, "%#06X");

    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardRFVerifyStackPointerFunctionPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, HotPatchTableOffset, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, Reserved3, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, EnclaveConfigurationPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, VolatileMetadataPointer, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardEHContinuationTable, "%#010X");
    PRINT_LC_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY32, LoadConfigDirectory32, AvailableSize, GuardEHContinuationCount, "%#010X");
}


DWORD LoadConfig(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有LoadConfig.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)
        ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size, &FoundHeader);
    if (LoadConfigDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    /*
    可读取的范围：
    1. 结构体自己的 Size 是权威值(加载器也用它判断结构版本)，它可能比当前 SDK 的结构短(老链接器)，
       数据目录里的 Size 反而可能是陈旧的(实测有 Size=0xC0 而数据目录只写 0x40 的文件)；
    2. 但无论如何不能越过所在节的原始数据或文件本身。
    */
    DWORD struct_offset = (DWORD)((PBYTE)LoadConfigDirectory - Data);
    DWORD available = Size - struct_offset;
    if (FoundHeader) {
        DWORD section_end = FoundHeader->PointerToRawData + FoundHeader->SizeOfRawData;
        if (section_end > struct_offset && section_end - struct_offset < available) {
            available = section_end - struct_offset;
        }
    }

    if (LoadConfigDirectory->Size != 0 && LoadConfigDirectory->Size < available) {
        available = LoadConfigDirectory->Size;
    }

    printf("Load Config Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("文件中的结构大小:%#010X.\r\n", available);
    printf("\r\n");

    //一下数据的有些成员是链表/数组，有待进一步的解析。

    if (IsPE32Ex(Data, Size)) {
        PrintLoadConfig64((PIMAGE_LOAD_CONFIG_DIRECTORY64)LoadConfigDirectory, available);
    } else {
        PrintLoadConfig32((PIMAGE_LOAD_CONFIG_DIRECTORY32)LoadConfigDirectory, available);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD LoadConfig(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, LoadConfig);
}

#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


LPWSTR UTF8ToWide(IN PCHAR utf8)
/*
得到的内存有调用者释放。
*/
{
    int cchWideChar = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, 0, 0);

    LPWSTR pws = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cchWideChar * 4);
    _ASSERTE(pws);

    int ret = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pws, cchWideChar);//utf8->Unicode
    _ASSERTE(ret);

    return pws;
}


void GetDataDirectory(_In_ PBYTE Data, 
                      _In_ DWORD Size,
                      _In_ BYTE index, 
                      _Out_ PIMAGE_DATA_DIRECTORY DataDirectory)
{
    DataDirectory->VirtualAddress = 0;
    DataDirectory->Size = 0;

    if (!IsValidPE(Data, Size)) {
        return;
    }

    _ASSERTE(index <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
    _ASSERTE(NtHeader);

    PIMAGE_DATA_DIRECTORY data_directory = NULL;

    bool IsPe64 = IsPE32Ex(Data, Size);
    if (IsPe64) {
        PIMAGE_OPTIONAL_HEADER64 OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeader->OptionalHeader;

        data_directory = &OptionalHeader->DataDirectory[0];

        _ASSERTE(IMAGE_NUMBEROF_DIRECTORY_ENTRIES == OptionalHeader->NumberOfRvaAndSizes);
    } else {
        PIMAGE_OPTIONAL_HEADER32 OptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&NtHeader->OptionalHeader;

        data_directory = &OptionalHeader->DataDirectory[0];

        _ASSERTE(IMAGE_NUMBEROF_DIRECTORY_ENTRIES == OptionalHeader->NumberOfRvaAndSizes);
    }

    DataDirectory->VirtualAddress = data_directory[index].VirtualAddress;
    DataDirectory->Size = data_directory[index].Size;
}


UINT Rva2Va(_In_ PBYTE Data, _In_ UINT rva)
/*
返回0表示失败，其他的是在文件中的偏移。
*/
{
    UINT offset = 0;//返回值。

    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
    _ASSERTE(NtHeader);
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&NtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)OptionalHeader + FileHeader->SizeOfOptionalHeader);//必须加(ULONG),不然出错.

    //注意：有个宏叫IMAGE_FIRST_SECTION。

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++)
    {
        if (rva >= SectionHeader[i].VirtualAddress && rva <= (SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)) {
            offset = rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
            break;
        }
    }

    return offset;
}


void GetSectionCharacteristics(_In_ DWORD Characteristics,
                               _Out_writes_(cchDest) PCHAR String,
                               _In_ size_t cchDest
)
{
    if (Characteristics & IMAGE_SCN_SCALE_INDEX) {
        StringCchCatA(String, cchDest, "SCALE_INDEX ");
    }

    if (Characteristics & IMAGE_SCN_TYPE_NO_PAD) {
        StringCchCatA(String, cchDest, "TYPE_NO_PAD ");
    }

    if (Characteristics & IMAGE_SCN_CNT_CODE) {
        StringCchCatA(String, cchDest, "CNT_CODE ");
    }

    if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        StringCchCatA(String, cchDest, "INITIALIZED_DATA ");
    }

    if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
        StringCchCatA(String, cchDest, "CNT_UNINITIALIZED_DATA ");
    }

    if (Characteristics & IMAGE_SCN_LNK_OTHER) {
        StringCchCatA(String, cchDest, "LNK_OTHER ");
    }

    if (Characteristics & IMAGE_SCN_LNK_INFO) {
        StringCchCatA(String, cchDest, "LNK_INFO ");
    }

    if (Characteristics & IMAGE_SCN_LNK_REMOVE) {
        StringCchCatA(String, cchDest, "LNK_REMOVE ");
    }

    if (Characteristics & IMAGE_SCN_LNK_COMDAT) {
        StringCchCatA(String, cchDest, "LNK_COMDAT ");
    }

    if (Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) {
        StringCchCatA(String, cchDest, "NO_DEFER_SPEC_EXC ");
    }

    if (Characteristics & IMAGE_SCN_GPREL) {
        StringCchCatA(String, cchDest, "GPREL ");
    }

    if (Characteristics & IMAGE_SCN_MEM_FARDATA) {
        StringCchCatA(String, cchDest, "MEM_FARDATA ");
    }

    if (Characteristics & IMAGE_SCN_MEM_PURGEABLE) {
        StringCchCatA(String, cchDest, "MEM_PURGEABLE ");
    }

    if (Characteristics & IMAGE_SCN_MEM_16BIT) {
        StringCchCatA(String, cchDest, "MEM_16BIT ");
    }

    if (Characteristics & IMAGE_SCN_MEM_LOCKED) {
        StringCchCatA(String, cchDest, "MEM_LOCKED ");
    }

    if (Characteristics & IMAGE_SCN_MEM_PRELOAD) {
        StringCchCatA(String, cchDest, "MEM_PRELOAD ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_1BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_1BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_2BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_2BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_4BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_4BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_8BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_8BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_16BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_16BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_32BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_32BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_64BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_64BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_128BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_128BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_256BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_256BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_512BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_512BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_1024BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_1024BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_2048BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_2048BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_4096BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_4096BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_8192BYTES) {
        StringCchCatA(String, cchDest, "ALIGN_8192BYTES ");
    }

    if (Characteristics & IMAGE_SCN_ALIGN_MASK) {
        StringCchCatA(String, cchDest, "ALIGN_MASK ");
    }

    if (Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) {
        StringCchCatA(String, cchDest, "LNK_NRELOC_OVFL ");
    }

    if (Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        StringCchCatA(String, cchDest, "MEM_DISCARDABLE ");
    }

    if (Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        StringCchCatA(String, cchDest, "MEM_NOT_CACHED ");
    }

    if (Characteristics & IMAGE_SCN_MEM_NOT_PAGED) {
        StringCchCatA(String, cchDest, "MEM_NOT_PAGED ");
    }

    if (Characteristics & IMAGE_SCN_MEM_SHARED) {
        StringCchCatA(String, cchDest, "MEM_SHARED ");
    }

    if (Characteristics & IMAGE_SCN_MEM_EXECUTE) {
        StringCchCatA(String, cchDest, "MEM_EXECUTE ");
    }

    if (Characteristics & IMAGE_SCN_MEM_READ) {
        StringCchCatA(String, cchDest, "MEM_READ ");
    }

    if (Characteristics & IMAGE_SCN_MEM_WRITE) {
        StringCchCatA(String, cchDest, "MEM_WRITE ");
    }
}


void GetDllCharacteristics(_In_ WORD Characteristics,
                           _Out_writes_(cchDest) PCHAR String,
                           _In_ size_t cchDest
)
{
    if (Characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
        StringCchCatA(String, cchDest, "HIGH_ENTROPY_VA ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        StringCchCatA(String, cchDest, "DYNAMIC_BASE ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        StringCchCatA(String, cchDest, "FORCE_INTEGRITY ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
        StringCchCatA(String, cchDest, "NX_COMPAT ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) {
        StringCchCatA(String, cchDest, "NO_ISOLATION ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
        StringCchCatA(String, cchDest, "NO_SEH ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) {
        StringCchCatA(String, cchDest, "NO_BIND ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) {
        StringCchCatA(String, cchDest, "APPCONTAINER ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) {
        StringCchCatA(String, cchDest, "WDM_DRIVER ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        StringCchCatA(String, cchDest, "GUARD_CF ");
    }

    if (Characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) {
        StringCchCatA(String, cchDest, "TERMINAL_SERVER_AWARE ");
    }
}


PCSTR GetSubsystem(_In_ WORD Subsystem)
{
    PCSTR SubsystemString = NULL;

    switch (Subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:
        SubsystemString = "UNKNOWN";
        break;
    case IMAGE_SUBSYSTEM_NATIVE:
        SubsystemString = "NATIVE";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        SubsystemString = "WINDOWS_GUI";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        SubsystemString = "WINDOWS_CUI";
        break;
    case IMAGE_SUBSYSTEM_OS2_CUI:
        SubsystemString = "OS2_CUI";
        break;
    case IMAGE_SUBSYSTEM_POSIX_CUI:
        SubsystemString = "POSIX_CUI";
        break;
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        SubsystemString = "NATIVE_WINDOWS";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        SubsystemString = "WINDOWS_CE_GUI";
        break;
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        SubsystemString = "EFI_APPLICATION";
        break;
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        SubsystemString = "EFI_BOOT_SERVICE_DRIVER";
        break;
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        SubsystemString = "EFI_RUNTIME_DRIVER";
        break;
    case IMAGE_SUBSYSTEM_EFI_ROM:
        SubsystemString = "EFI_ROM";
        break;
    case IMAGE_SUBSYSTEM_XBOX:
        SubsystemString = "XBOX";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        SubsystemString = "WINDOWS_BOOT_APPLICATION";
        break;
    case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
        SubsystemString = "XBOX_CODE_CATALOG";
        break;
    default:
        LOGA(ERROR_LEVEL, "SUBSYSTEM:%#X", Subsystem);
        SubsystemString = "未定义";
        break;
    }

    return SubsystemString;
}


void TimeStampToFileTime(INT64 timeStamp, FILETIME & fileTime)
{
    INT64 nll = timeStamp * 10000000 + 116444736000000000;
    fileTime.dwLowDateTime = (DWORD)nll;
    fileTime.dwHighDateTime = nll >> 32;
}


void FileTimeToLocalTimeA(PFILETIME ft, char * time)
/*
把FileTime转换为本地时间打印。
*/
{
    FILETIME lft;
    BOOL B = FileTimeToLocalFileTime(ft, &lft);
    _ASSERTE(B);

    SYSTEMTIME st;
    //GetLocalTime(&st);
    B = FileTimeToSystemTime(&lft, &st);
    _ASSERTE(B);

    //SystemTimeToTzSpecificLocalTime

    //格式：2016-07-11 17:35:54      
    wsprintfA(time,
              "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear,
              st.wMonth,
              st.wDay,
              st.wHour,
              st.wMinute,
              st.wSecond);

    //size_t cb = lstrlen(time) * sizeof(wchar_t);
}


void GetTimeDateStamp(_In_ DWORD TimeDateStamp, _Out_writes_(MAX_PATH) PCHAR String)
{
    FILETIME FileTime = {0};
    TimeStampToFileTime(TimeDateStamp, FileTime);

    FileTimeToLocalTimeA(&FileTime, String);
}


void GetCharacteristics(_In_ WORD Characteristics,
                        _Out_writes_(cchDest) PCHAR String,
                        _In_ size_t cchDest
)
/*
这个函数不能用BitTest，因为它是从零开始的，但是这个结构没有0，从1开始的。

BitTest的第二个数必须是大于零的，不能是负数。
_bittest64需要_AMD64_。
*/
{
    _ASSERTE(String);
    //String[0] = 0;

    if (Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        StringCchCatA(String, cchDest, "RELOCS_STRIPPED ");
    }

    if (Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        StringCchCatA(String, cchDest, "EXECUTABLE_IMAGE ");
    }

    if (Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) {
        StringCchCatA(String, cchDest, "LINE_NUMS_STRIPPED ");
    }

    if (Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) {
        StringCchCatA(String, cchDest, "LOCAL_SYMS_STRIPPED ");
    }

    if (Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) {
        StringCchCatA(String, cchDest, "AGGRESIVE_WS_TRIM ");
    }

    if (Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        StringCchCatA(String, cchDest, "LARGE_ADDRESS_AWARE ");
    }

    if (Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) {
        StringCchCatA(String, cchDest, "BYTES_REVERSED_LO ");
    }

    if (Characteristics & IMAGE_FILE_32BIT_MACHINE) {
        StringCchCatA(String, cchDest, "32BIT_MACHINE ");
    }

    if (Characteristics & IMAGE_FILE_DEBUG_STRIPPED) {
        StringCchCatA(String, cchDest, "DEBUG_STRIPPED ");
    }

    if (Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
        StringCchCatA(String, cchDest, "REMOVABLE_RUN_FROM_SWAP ");
    }

    if (Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) {
        StringCchCatA(String, cchDest, "NET_RUN_FROM_SWAP ");
    }

    if (Characteristics & IMAGE_FILE_SYSTEM) {
        StringCchCatA(String, cchDest, "SYSTEM ");
    }

    if (Characteristics & IMAGE_FILE_DLL) {
        StringCchCatA(String, cchDest, "DLL ");
    }

    if (Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
        StringCchCatA(String, cchDest, "UP_SYSTEM_ONLY ");
    }

    if (Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) {
        StringCchCatA(String, cchDest, "BYTES_REVERSED_HI ");
    }
}


PCSTR GetMachine(_In_ WORD Machine)
{
    PCSTR MachineString = NULL;

    switch (Machine) {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        MachineString = "适用于任何类型处理器";
        break;
    case IMAGE_FILE_MACHINE_TARGET_HOST:
        MachineString = "Useful for indicating we want to interact with the host and not a WoW guest";
        break;
    case IMAGE_FILE_MACHINE_I386:
        MachineString = "Intel 386";
        break;
    case IMAGE_FILE_MACHINE_R3000:
        MachineString = "MIPS little-endian, 0x160 big-endian";
        break;
    case IMAGE_FILE_MACHINE_R4000:
        MachineString = "MIPS little-endian";
        break;
    case IMAGE_FILE_MACHINE_R10000:
        MachineString = "MIPS little-endian";
        break;
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
        MachineString = "MIPS little-endian WCE v2";
        break;
    case IMAGE_FILE_MACHINE_ALPHA:
        MachineString = "Alpha_AXP";
        break;
    case IMAGE_FILE_MACHINE_SH3:
        MachineString = "SH3 little-endian";
        break;
    case IMAGE_FILE_MACHINE_SH3DSP:
        MachineString = "IMAGE_FILE_MACHINE_SH3DSP";
        break;
    case IMAGE_FILE_MACHINE_SH3E:
        MachineString = "SH3E little-endian";
        break;
    case IMAGE_FILE_MACHINE_SH4:
        MachineString = "SH4 little-endian";
        break;
    case IMAGE_FILE_MACHINE_SH5:
        MachineString = "SH5";
        break;
    case IMAGE_FILE_MACHINE_ARM:
        MachineString = "ARM Little-Endian";
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        MachineString = "ARM Thumb/Thumb-2 Little-Endian";
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        MachineString = "ARM Thumb-2 Little-Endian";
        break;
    case IMAGE_FILE_MACHINE_AM33:
        MachineString = "IMAGE_FILE_MACHINE_AM33";
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        MachineString = "IBM PowerPC Little-Endian";
        break;
    case IMAGE_FILE_MACHINE_POWERPCFP:
        MachineString = "IMAGE_FILE_MACHINE_POWERPCFP";
        break;
    case IMAGE_FILE_MACHINE_IA64:
        MachineString = "Intel 64";
        break;
    case IMAGE_FILE_MACHINE_MIPS16:
        MachineString = "MIPS";
        break;
    case IMAGE_FILE_MACHINE_ALPHA64:
        MachineString = "ALPHA64";
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU:
        MachineString = "MIPS";
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU16:
        MachineString = "MIPS";
        break;
    case IMAGE_FILE_MACHINE_TRICORE:
        MachineString = "Infineon";
        break;
    case IMAGE_FILE_MACHINE_CEF:
        MachineString = "IMAGE_FILE_MACHINE_CEF";
        break;
    case IMAGE_FILE_MACHINE_EBC:
        MachineString = "EFI Byte Code";
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        MachineString = "AMD64 (K8)";
        break;
    case IMAGE_FILE_MACHINE_M32R:
        MachineString = "M32R little-endian";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        MachineString = "ARM64 Little-Endian";
        break;
    case IMAGE_FILE_MACHINE_CEE:
        MachineString = "IMAGE_FILE_MACHINE_CEE";
        break;
    default:
        LOGA(ERROR_LEVEL, "Machine:%#X", Machine);
        MachineString = "未知";
        break;
    }

    return MachineString;
}


BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

#ifdef _WIN64
    // 64-bit code, obviously not running in a 32-bit process
    return false;
#endif

#pragma warning(push)
#pragma warning(disable:4702)
    HMODULE ModuleHandle = GetModuleHandle(TEXT("kernel32"));
    if (NULL != ModuleHandle) {
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(ModuleHandle,
                                                                                   "IsWow64Process");
        if (NULL != fnIsWow64Process) {
            if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64)) {
                // handle error
            }
        }
    }

    return bIsWow64;
#pragma warning(pop)
}


bool IsValidPE(_In_ PBYTE Data, _In_ DWORD Size)
{
    bool ret = false;

    __try {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Data;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            __leave;
        }

        PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
        switch (NtHeader->Signature) {
        case IMAGE_OS2_SIGNATURE:
            LOGA(ERROR_LEVEL, "恭喜你:发现一个NE文件!");
            break;
        case IMAGE_OS2_SIGNATURE_LE://IMAGE_VXD_SIGNATURE
            LOGA(ERROR_LEVEL, "恭喜你:发现一个LE文件!");
            break;
        case IMAGE_NT_SIGNATURE:
            ret = true;
            break;
        default:
            //LOGA(ERROR_LEVEL, "Signature:%X", nt_headers->Signature);
            break;
        }

#if 0
        ULONG  ntSignature = (ULONG)dos_header + dos_header->e_lfanew;
        unsigned short int other = *(unsigned short int *)ntSignature;
        ntSignature = *(ULONG *)ntSignature;

        if (IMAGE_OS2_SIGNATURE == other) {
            LOGA(ERROR_LEVEL, "恭喜你:发现一个NE文件!");
            __leave;
        }

        if (IMAGE_OS2_SIGNATURE_LE == other) //IMAGE_VXD_SIGNATURE
        {
            LOGA(ERROR_LEVEL, "恭喜你:发现一个LE文件!");
            __leave;
        }

        if (IMAGE_NT_SIGNATURE == ntSignature) {
            ret = true;
        }
#endif // 0
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ret = GetExceptionCode();
        LOGA(ERROR_LEVEL, "ExceptionCode:%#x", ret);
    }

    return ret;
}


bool IsPE32Ex(_In_ PBYTE Data, _In_ DWORD Size)
{
    bool ret = false;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    __try {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Data;
        _ASSERTE(IMAGE_DOS_SIGNATURE == DosHeader->e_magic);

        PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
        _ASSERTE(NtHeader);

        /*
        对于可选头的标准域(排除最后一个BaseOfData)来说，是32位的可选头和64位的可选头无所谓，因为偏移都是一样的。
        */
        PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
        switch (OptionalHeader->Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            //这是一个普通的PE文件
            break;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            ret = true;//这是一个的PE32+文件
            break;
        case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
            LOGA(ERROR_LEVEL, "恭喜你:发现一个ROM映像!");
            break;
        default:
            LOGA(ERROR_LEVEL, "Magic:%#X!", OptionalHeader->Magic);
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ret = GetExceptionCode();
        LOGA(ERROR_LEVEL, "ExceptionCode:%#x", ret);
    }

    return ret;
}


DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack)
{
    DWORD LastError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapFile = NULL;
    PBYTE FileContent = NULL;

    if (IsWow64()) {//在wow64下关闭文件重定向。
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(FALSE);
        _ASSERTE(bRet);
    }

    __try {
        hFile = CreateFile(FileName,
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFile");
            __leave;
        }

        LARGE_INTEGER FileSize = {0};
        if (0 == GetFileSizeEx(hFile, &FileSize)) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("GetFileSizeEx");
            __leave;
        }

        if (0 == FileSize.QuadPart) {//如果文件大小为0.
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        if (FileSize.HighPart) {//暂时不支持大于4G的文件。
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* 空文件则返回失败 */
        if (hMapFile == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        FileContent = (PBYTE)MapViewOfFile(hMapFile, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);
        if (FileContent == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        if (CallBack) {
            __try {
                LastError = CallBack(FileContent, FileSize.LowPart);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                LastError = GetExceptionCode();
                LOGA(ERROR_LEVEL, "ExceptionCode:%#x", LastError);
            }
        }
    } __finally {
        if (FileContent) {
            UnmapViewOfFile(FileContent);
        }

        if (hMapFile) {
            CloseHandle(hMapFile);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }
    }

    if (IsWow64()) {
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(TRUE);//Enable WOW64 file system redirection. 
        _ASSERTE(bRet);
    }

    return LastError;
}

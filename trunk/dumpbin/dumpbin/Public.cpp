#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


LPWSTR UTF8ToWide(IN PCHAR utf8)
/*
�õ����ڴ��е������ͷš�
*/
{
    int cchWideChar = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, 0, 0);

    LPWSTR pws = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cchWideChar * 4);
    _ASSERTE(pws);

    int ret = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pws, cchWideChar);//utf8->Unicode
    _ASSERTE(ret);

    return pws;
}


void GetDataDirectory(_In_ PBYTE Data, _In_ DWORD Size, _In_ BYTE index, _Out_ PIMAGE_DATA_DIRECTORY DataDirectory)
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
����0��ʾʧ�ܣ������������ļ��е�ƫ�ơ�
*/
{
    UINT offset = 0;//����ֵ��

    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
    _ASSERTE(NtHeader);
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&NtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)OptionalHeader + FileHeader->SizeOfOptionalHeader);//�����(ULONG),��Ȼ����.

    //ע�⣺�и����IMAGE_FIRST_SECTION��

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++) {
        if (rva >= SectionHeader[i].VirtualAddress && rva <= (SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)) {
            offset = rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
            break;
        }
    }

    return offset;
}


// Performance optimization: Build string more efficiently by tracking position
void GetSectionCharacteristics(_In_ DWORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    PCHAR ptr = String;
    size_t remaining = cchDest;

    #define APPEND_IF_SET(flag, text) \
        if ((Characteristics & flag) && remaining > 0) { \
            size_t len = strlen(text); \
            if (len < remaining) { \
                memcpy(ptr, text, len); \
                ptr += len; \
                remaining -= len; \
            } \
        }

    APPEND_IF_SET(IMAGE_SCN_SCALE_INDEX, "SCALE_INDEX ")
    APPEND_IF_SET(IMAGE_SCN_TYPE_NO_PAD, "TYPE_NO_PAD ")
    APPEND_IF_SET(IMAGE_SCN_CNT_CODE, "CNT_CODE ")
    APPEND_IF_SET(IMAGE_SCN_CNT_INITIALIZED_DATA, "INITIALIZED_DATA ")
    APPEND_IF_SET(IMAGE_SCN_CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA ")
    APPEND_IF_SET(IMAGE_SCN_LNK_OTHER, "LNK_OTHER ")
    APPEND_IF_SET(IMAGE_SCN_LNK_INFO, "LNK_INFO ")
    APPEND_IF_SET(IMAGE_SCN_LNK_REMOVE, "LNK_REMOVE ")
    APPEND_IF_SET(IMAGE_SCN_LNK_COMDAT, "LNK_COMDAT ")
    APPEND_IF_SET(IMAGE_SCN_NO_DEFER_SPEC_EXC, "NO_DEFER_SPEC_EXC ")
    APPEND_IF_SET(IMAGE_SCN_GPREL, "GPREL ")
    APPEND_IF_SET(IMAGE_SCN_MEM_FARDATA, "MEM_FARDATA ")
    APPEND_IF_SET(IMAGE_SCN_MEM_PURGEABLE, "MEM_PURGEABLE ")
    APPEND_IF_SET(IMAGE_SCN_MEM_16BIT, "MEM_16BIT ")
    APPEND_IF_SET(IMAGE_SCN_MEM_LOCKED, "MEM_LOCKED ")
    APPEND_IF_SET(IMAGE_SCN_MEM_PRELOAD, "MEM_PRELOAD ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_1BYTES, "ALIGN_1BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_2BYTES, "ALIGN_2BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_4BYTES, "ALIGN_4BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_8BYTES, "ALIGN_8BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_16BYTES, "ALIGN_16BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_32BYTES, "ALIGN_32BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_64BYTES, "ALIGN_64BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_128BYTES, "ALIGN_128BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_256BYTES, "ALIGN_256BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_512BYTES, "ALIGN_512BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_1024BYTES, "ALIGN_1024BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_2048BYTES, "ALIGN_2048BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_4096BYTES, "ALIGN_4096BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_8192BYTES, "ALIGN_8192BYTES ")
    APPEND_IF_SET(IMAGE_SCN_ALIGN_MASK, "ALIGN_MASK ")
    APPEND_IF_SET(IMAGE_SCN_LNK_NRELOC_OVFL, "LNK_NRELOC_OVFL ")
    APPEND_IF_SET(IMAGE_SCN_MEM_DISCARDABLE, "MEM_DISCARDABLE ")
    APPEND_IF_SET(IMAGE_SCN_MEM_NOT_CACHED, "MEM_NOT_CACHED ")
    APPEND_IF_SET(IMAGE_SCN_MEM_NOT_PAGED, "MEM_NOT_PAGED ")
    APPEND_IF_SET(IMAGE_SCN_MEM_SHARED, "MEM_SHARED ")
    APPEND_IF_SET(IMAGE_SCN_MEM_EXECUTE, "MEM_EXECUTE ")
    APPEND_IF_SET(IMAGE_SCN_MEM_READ, "MEM_READ ")
    APPEND_IF_SET(IMAGE_SCN_MEM_WRITE, "MEM_WRITE ")
    
    #undef APPEND_IF_SET
    
    if (remaining > 0) {
        *ptr = '\0';
    }
}


// Performance optimization: Build string more efficiently by tracking position
void GetDllCharacteristics(_In_ WORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    PCHAR ptr = String;
    size_t remaining = cchDest;

    #define APPEND_IF_SET(flag, text) \
        if ((Characteristics & flag) && remaining > 0) { \
            size_t len = strlen(text); \
            if (len < remaining) { \
                memcpy(ptr, text, len); \
                ptr += len; \
                remaining -= len; \
            } \
        }

    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "NX_COMPAT ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "APPCONTAINER ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_GUARD_CF, "GUARD_CF ")
    APPEND_IF_SET(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE ")
    
    #undef APPEND_IF_SET
    
    if (remaining > 0) {
        *ptr = '\0';
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
        SubsystemString = "δ����";
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
��FileTimeת��Ϊ����ʱ���ӡ��
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

    //��ʽ��2016-07-11 17:35:54      
    wsprintfA(time, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    //size_t cb = lstrlen(time) * sizeof(wchar_t);
}


void GetTimeDateStamp(_In_ DWORD TimeDateStamp, _Out_writes_(MAX_PATH) PCHAR String)
{
    FILETIME FileTime = {0};
    TimeStampToFileTime(TimeDateStamp, FileTime);

    FileTimeToLocalTimeA(&FileTime, String);
}


// Performance optimization: Build string more efficiently by tracking position
void GetCharacteristics(_In_ WORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    _ASSERTE(String);
    
    PCHAR ptr = String;
    size_t remaining = cchDest;

    #define APPEND_IF_SET(flag, text) \
        if ((Characteristics & flag) && remaining > 0) { \
            size_t len = strlen(text); \
            if (len < remaining) { \
                memcpy(ptr, text, len); \
                ptr += len; \
                remaining -= len; \
            } \
        }

    APPEND_IF_SET(IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED ")
    APPEND_IF_SET(IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE ")
    APPEND_IF_SET(IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED ")
    APPEND_IF_SET(IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED ")
    APPEND_IF_SET(IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM ")
    APPEND_IF_SET(IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE ")
    APPEND_IF_SET(IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO ")
    APPEND_IF_SET(IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE ")
    APPEND_IF_SET(IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED ")
    APPEND_IF_SET(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP ")
    APPEND_IF_SET(IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP ")
    APPEND_IF_SET(IMAGE_FILE_SYSTEM, "SYSTEM ")
    APPEND_IF_SET(IMAGE_FILE_DLL, "DLL ")
    APPEND_IF_SET(IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY ")
    APPEND_IF_SET(IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI ")
    
    #undef APPEND_IF_SET
    
    if (remaining > 0) {
        *ptr = '\0';
    }
}


PCSTR GetMachine(_In_ WORD Machine)
{
    PCSTR MachineString = NULL;

    switch (Machine) {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        MachineString = "�������κ����ʹ�����";
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
        MachineString = "δ֪";
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
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(ModuleHandle, "IsWow64Process");
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
            LOGA(ERROR_LEVEL, "��ϲ��:����һ��NE�ļ�!");
            break;
        case IMAGE_OS2_SIGNATURE_LE://IMAGE_VXD_SIGNATURE
            LOGA(ERROR_LEVEL, "��ϲ��:����һ��LE�ļ�!");
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
            LOGA(ERROR_LEVEL, "��ϲ��:����һ��NE�ļ�!");
            __leave;
        }

        if (IMAGE_OS2_SIGNATURE_LE == other) //IMAGE_VXD_SIGNATURE
        {
            LOGA(ERROR_LEVEL, "��ϲ��:����һ��LE�ļ�!");
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
        ���ڿ�ѡͷ�ı�׼��(�ų����һ��BaseOfData)��˵����32λ�Ŀ�ѡͷ��64λ�Ŀ�ѡͷ����ν����Ϊƫ�ƶ���һ���ġ�
        */
        PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
        switch (OptionalHeader->Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            //����һ����ͨ��PE�ļ�
            break;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            ret = true;//����һ����PE32+�ļ�
            break;
        case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
            LOGA(ERROR_LEVEL, "��ϲ��:����һ��ROMӳ��!");
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

    if (IsWow64()) {//��wow64�¹ر��ļ��ض���
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(FALSE);
        _ASSERTE(bRet);
    }

    __try {
        hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

        if (0 == FileSize.QuadPart) {//����ļ���СΪ0.
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        if (FileSize.HighPart) {//��ʱ��֧�ִ���4G���ļ���
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* ���ļ��򷵻�ʧ�� */
        if (hMapFile == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        FileContent = (PBYTE)MapViewOfFile(hMapFile, SECTION_MAP_READ, NULL, NULL, 0/*ӳ������*/);
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

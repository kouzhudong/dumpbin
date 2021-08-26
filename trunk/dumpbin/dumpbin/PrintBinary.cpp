#include "pch.h"
#include "PrintBinary.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void BinaryToStringA(BYTE * lpMapAddress, DWORD dwFileSize)
{
    __try {
        DWORD   dwFlags = CRYPT_STRING_HEXASCIIADDR;
        BOOL B = 0;

        LPSTR pszString2 = 0;
        DWORD  pcchString = 0;
        B = CryptBinaryToStringA((BYTE *)lpMapAddress, dwFileSize, dwFlags, pszString2, &pcchString);
        if (B == false) {
            return;
        }

        pcchString = pcchString * sizeof(wchar_t);
        pszString2 = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcchString);
        if (pszString2 == NULL) {
            printf("Failed to allocate on heap.\n");
            return;
        }

        //注意单字符和宽字符的编码是不一样的。
        B = CryptBinaryToStringA((BYTE *)lpMapAddress, dwFileSize, dwFlags, pszString2, &pcchString);
        if (B == false) {
            HeapFree(GetProcessHeap(), 0, pszString2);
            return;
        }

        printf("%s\n", pszString2);

        HeapFree(GetProcessHeap(), 0, pszString2);
        return;
    } __except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        _tprintf(TEXT("发生异常了！\n"));
    }
}


void BinaryToStringW(BYTE * lpMapAddress, DWORD dwFileSize)
{
    __try {
        DWORD   dwFlags = CRYPT_STRING_HEXASCIIADDR;
        BOOL B = 0;

        LPWSTR String = 0;
        DWORD  pcchString = 0;
        B = CryptBinaryToStringW(lpMapAddress, dwFileSize, dwFlags, String, &pcchString);
        if (B == false) {
            return;
        }

        String = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcchString * sizeof(wchar_t));
        if (String == NULL) {
            printf("Failed to allocate on heap.\n");
            return;
        }

        //注意单字符和宽字符的编码是不一样的。
        B = CryptBinaryToStringW(lpMapAddress, dwFileSize, dwFlags, String, &pcchString);
        if (B == false) {
            HeapFree(GetProcessHeap(), 0, String);
            return;
        }

        printf("%ls\n", String);

        HeapFree(GetProcessHeap(), 0, String);
        return;
    } __except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        _tprintf(TEXT("发生异常了！\n"));
    }
}


DWORD PrintBinary(_In_ PBYTE Data, _In_ DWORD Size, _In_ DWORD Address, _In_ DWORD Length)
/*
Address应该叫Offset.
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    if (Address > Size) {
        return ret;
    }

    if (Length > Size) {
        return ret;
    }

    //反正是在异常处理里的，都不检查了。

    BinaryToStringA(Data + Address, Length);

#if 0
    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    PBYTE start = (PBYTE)ImageRvaToVa(NtHeaders, Data, Address, NULL);

    BinaryToStringA(start, Length);
#endif

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD PrintBinary(_In_ LPCWSTR FileName, _In_ LPCWSTR AddressString, _In_ LPCWSTR LengthString)
{
    DWORD Address = _wtoi(AddressString);
    DWORD Length = _wtoi(LengthString);

    //////////////////////////////////////////////////////////////////////////////////////////////

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

        __try {
            LastError = PrintBinary(FileContent, FileSize.LowPart, Address, Length);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LastError = GetExceptionCode();
            LOGA(ERROR_LEVEL, "ExceptionCode:%#x", LastError);
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

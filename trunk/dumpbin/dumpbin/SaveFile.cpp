#include "pch.h"
#include "SaveFile.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD SaveFile(_In_ PBYTE Data,
               _In_ DWORD Size,
               _In_ DWORD Address,
               _In_ DWORD Length,
               _In_ LPCWSTR NewFileName
)
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

    HANDLE hFile = CreateFile(NewFileName,
                               FILE_ALL_ACCESS,
                               FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
                               NULL,
                               CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        DWORD LastError = GetLastError();
        LOGA(ERROR_LEVEL, "LastError:%#d, NewFileName:%ls", LastError, NewFileName);
        LogApiErrMsg("CreateFile");
        return LastError;
    }

    DWORD writeten = 0;
    BOOL B = WriteFile(hFile, Data + Address, Length, &writeten, NULL);
    _ASSERTE(B);

    B = CloseHandle(hFile);
    _ASSERTE(B);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD SaveFile(_In_ LPCWSTR FileName, 
               _In_ LPCWSTR AddressString, 
               _In_ LPCWSTR LengthString,
               _In_ LPCWSTR NewFileName)
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
            LastError = SaveFile(FileContent, FileSize.LowPart, Address, Length, NewFileName);
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

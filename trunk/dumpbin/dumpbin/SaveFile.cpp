#include "pch.h"
#include "SaveFile.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD SaveFile(_In_ PBYTE Data, _In_ DWORD Size, _In_ DWORD Address, _In_ DWORD Length, _In_ LPCWSTR NewFileName)
/*
Address是文件偏移(不是RVA)。
NewFileName 已存在时不覆盖，会直接失败(CREATE_NEW)。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    //整段数据都要落在文件里，Address + Length 不能越过文件尾。
    if (Address >= Size || Length > Size - Address) {
        LOGA(ERROR_LEVEL, "地址或长度越界, Address:%u, Length:%u, Size:%u", Address, Length, Size);
        return ERROR_INVALID_PARAMETER;
    }

    HANDLE hFile = CreateFile(NewFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        DWORD LastError = GetLastError();
        LOGA(ERROR_LEVEL, "LastError:%#d, NewFileName:%ls", LastError, NewFileName);
        LogApiErrMsg("CreateFile");
        return LastError;
    }

    DWORD written = 0;
    if (!WriteFile(hFile, Data + Address, Length, &written, NULL) || written != Length) {
        DWORD LastError = GetLastError();
        LOGA(ERROR_LEVEL, "WriteFile 失败, LastError:%#d, 期望:%u, 实际:%u", LastError, Length, written);
        CloseHandle(hFile);
        return (LastError != ERROR_SUCCESS) ? LastError : ERROR_WRITE_FAULT;
    }

    CloseHandle(hFile);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//PeCallBack 只有 (Data, Size)，命令行参数通过文件级变量带进回调(命令行工具是单线程的)。
static DWORD g_save_file_address = 0;
static DWORD g_save_file_length = 0;
static LPCWSTR g_save_file_new_name = NULL;


static DWORD SaveFileCallback(_In_ PBYTE Data, _In_ DWORD Size)
{
    return SaveFile(Data, Size, g_save_file_address, g_save_file_length, g_save_file_new_name);
}


DWORD SaveFile(_In_ LPCWSTR FileName, _In_ LPCWSTR AddressString, _In_ LPCWSTR LengthString, _In_ LPCWSTR NewFileName)
{
    g_save_file_address = _wtoi(AddressString);
    g_save_file_length = _wtoi(LengthString);
    g_save_file_new_name = NewFileName;

    return MapFile(FileName, SaveFileCallback);
}

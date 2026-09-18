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

        //A 版本的 pcchString 是单字节字符数，直接就是字节数，不用再乘 sizeof(wchar_t)。
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
Address是文件偏移(不是RVA)。
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

    BinaryToStringA(Data + Address, Length);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//PeCallBack 只有 (Data, Size)，命令行参数通过文件级变量带进回调(命令行工具是单线程的)。
static DWORD g_print_binary_address = 0;
static DWORD g_print_binary_length = 0;


static DWORD PrintBinaryCallback(_In_ PBYTE Data, _In_ DWORD Size)
{
    return PrintBinary(Data, Size, g_print_binary_address, g_print_binary_length);
}


DWORD PrintBinary(_In_ LPCWSTR FileName, _In_ LPCWSTR AddressString, _In_ LPCWSTR LengthString)
{
    g_print_binary_address = _wtoi(AddressString);
    g_print_binary_length = _wtoi(LengthString);

    return MapFile(FileName, PrintBinaryCallback);
}

#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef BOOL(WINAPI * LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

typedef DWORD(*PeCallBack)(_In_ PBYTE Data, _In_ DWORD Size);//回调函数的原型。

DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack);

bool IsValidPE(_In_ PBYTE Data, _In_ DWORD Size);
bool IsPE32Ex(_In_ PBYTE Data, _In_ DWORD Size);

PCSTR GetMachine(_In_ WORD Machine);

void GetCharacteristics(_In_ WORD Characteristics,
                        _Out_writes_(cchDest) PCHAR String,
                        _In_ size_t cchDest);

void GetTimeDateStamp(_In_ DWORD TimeDateStamp, _Out_writes_(MAX_PATH) PCHAR String);

PCSTR GetSubsystem(_In_ WORD Subsystem);

void GetDllCharacteristics(_In_ WORD Characteristics,
                           _Out_writes_(cchDest) PCHAR String,
                           _In_ size_t cchDest);

void GetSectionCharacteristics(_In_ DWORD Characteristics,
                               _Out_writes_(cchDest) PCHAR String,
                               _In_ size_t cchDest);

UINT Rva2Va(_In_ PBYTE Data, _In_ UINT rva);

void GetDataDirectory(_In_ PBYTE Data,
                      _In_ DWORD Size,
                      _In_ BYTE index,
                      _Out_ PIMAGE_DATA_DIRECTORY DataDirectory);

BOOL IsWow64();

LPWSTR UTF8ToWide(IN PCHAR utf8);

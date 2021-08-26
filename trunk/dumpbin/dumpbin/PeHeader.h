#pragma once

#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD DosHeader(_In_ LPCWSTR FileName);
DWORD FileHeader(_In_ LPCWSTR FileName);
DWORD OptionlHeader(_In_ LPCWSTR FileName);
DWORD SectionHeader(_In_ LPCWSTR FileName);
DWORD DataDirectory(_In_ LPCWSTR FileName);

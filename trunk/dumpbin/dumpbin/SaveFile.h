#pragma once

#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD SaveFile(_In_ LPCWSTR FileName,
               _In_ LPCWSTR AddressString,
               _In_ LPCWSTR LengthString,
               _In_ LPCWSTR NewFileName);

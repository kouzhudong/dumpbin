#pragma once

#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _BaseRelocBit {
    WORD Offset : 12;
    WORD Type : 4;//��4λ��    
} BaseRelocBit, * PBaseRelocBit;


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD BaseReloc(_In_ LPCWSTR FileName);
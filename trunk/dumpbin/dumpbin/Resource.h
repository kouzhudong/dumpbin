/*
谨记：
这里是纯PE的解析，不包括使用API的解析。
所以这里不包含使用API解析资源的内容。
*/

#pragma once

#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Resource(_In_ LPCWSTR FileName);

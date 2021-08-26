#pragma once

#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
http://www.debuginfo.com/articles/debuginfomatch.html
*/
#pragma warning(push)
#pragma warning(disable : 4200) //使用了非标准扩展: 结构/联合中的零大小数组
struct CV_INFO_PDB70
{
    DWORD  CvSignature;//equal to “RSDS”
    GUID Signature;
    DWORD Age;
    BYTE PdbFileName[];
};
#pragma warning(pop)  


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Debug(_In_ LPCWSTR FileName);

/*
文件的证书的解析有几种思路：
1.纯PE文件格式的解析，不用任何API。
  这是最初的想法，可惜现在还不了解证书的相关的结构和规范。
  解密ASN可用CryptDecodeObjectEx等API。
2.直接用获取证书的相关API，即WinTrust的相关函数。
3.ImageHlp相关的API，这个比较肤浅，但是能移除证书。
4.利用算法（CNG）相关API的解析，这个需要对算法（CNG）有深入的了解，这个在驱动亦能使用。
5.其他第三方库，
  如：openssl（如：d2i_PKCS7，OBJ_obj2nid，sk_X509_num，sk_X509_value，X509_get_issuer_name）等。
*/

#pragma once

#include "pch.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Security(_In_ LPCWSTR FileName);

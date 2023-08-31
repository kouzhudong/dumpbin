#include "pch.h"
#include "Security.h"
#include "Public.h"
#include "openssl.h"
#include "Public.h"
#include "..\lib\tiny-asn1\src\tiny-asn1.h"


#pragma warning(disable:6386)
#pragma warning(disable:6387)


//////////////////////////////////////////////////////////////////////////////////////////////////


PCSTR GetCertificateType(_In_ WORD CertificateType)
{
    PCSTR CertificateTypeStr = NULL;

    switch (CertificateType) {
    case WIN_CERT_TYPE_X509:
        CertificateTypeStr = "X509";
        break;
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        CertificateTypeStr = "PKCS_SIGNED_DATA";
        break;
    case WIN_CERT_TYPE_RESERVED_1:
        CertificateTypeStr = "RESERVED_1";
        break;
    case WIN_CERT_TYPE_TS_STACK_SIGNED:
        CertificateTypeStr = "TS_STACK_SIGNED";
        break;
    default:
        CertificateTypeStr = "未知";
        break;
    }

    return CertificateTypeStr;
}


PCSTR GetCertRevision(_In_ WORD wRevision)
{
    PCSTR string = NULL;

    switch (wRevision) {
    case WIN_CERT_REVISION_1_0:
        string = "1_0";
        break;
    case WIN_CERT_REVISION_2_0:
        string = "2_0";
        break;
    default:
        string = "未知";
        break;
    }

    return string;
}


void DumpCertInfo(PCERT_INFO CertInfo)
{
    _tprintf(_T("版本:%d.\n"), CertInfo->dwVersion + 1);

    _tprintf(_T("ObjId:%hs.\n"), CertInfo->SignatureAlgorithm.pszObjId);

    _tprintf(_T("公钥参数: "));
    DWORD dwData = CertInfo->SignatureAlgorithm.Parameters.cbData;
    for (DWORD n = 0; n < dwData; n++) {
        _tprintf(_T("%02x "), CertInfo->SignatureAlgorithm.Parameters.pbData[n]);
    }
    _tprintf(_T("\n"));

    // Print Serial Number.
    _tprintf(_T("序列号: "));
    dwData = CertInfo->SerialNumber.cbData;
    for (DWORD n = 0; n < dwData; n++) {
        _tprintf(_T("%02x "), CertInfo->SerialNumber.pbData[dwData - (n + 1)]);
    }
    _tprintf(_T("\n"));

    char NotBefore[MAX_PATH] = {0};
    FileTimeToLocalTimeA(&CertInfo->NotBefore, NotBefore);
    printf("有效期从:%s", NotBefore);

    char NotAfter[MAX_PATH] = {0};
    FileTimeToLocalTimeA(&CertInfo->NotAfter, NotAfter);
    printf("到:%s\n", NotAfter);

    _tprintf(_T("SubjectPublicKey Algorithm ObjId:%hs.\n"),
             CertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

    _tprintf(_T("SubjectPublicKey Algorithm Parameters: "));
    dwData = CertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData;
    for (DWORD n = 0; n < dwData; n++) {
        _tprintf(_T("%02x "), CertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData[dwData - (n + 1)]);
    }
    _tprintf(_T("\n"));

    _tprintf(_T("UnusedBits:%d.\n"), CertInfo->SubjectPublicKeyInfo.PublicKey.cUnusedBits);
    _tprintf(_T("公钥: "));
    dwData = CertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
    for (DWORD n = 0; n < dwData; n++) {
        _tprintf(_T("%02x "), CertInfo->SubjectPublicKeyInfo.PublicKey.pbData[n]);
    }
    _tprintf(_T("\n"));

    //还有IssuerUniqueId，SubjectUniqueId，cExtension等信息。

    _tprintf(_T("cExtension:%d.\n"), CertInfo->cExtension);
    _tprintf(_T("Extension ObjId:%hs.\n"), CertInfo->rgExtension->pszObjId);
    _tprintf(_T("Extension fCritical:%d.\n"), CertInfo->rgExtension->fCritical);
    _tprintf(_T("Extension Value: "));
    dwData = CertInfo->rgExtension->Value.cbData;
    for (DWORD n = 0; n < dwData; n++) {
        _tprintf(_T("%02x "), CertInfo->rgExtension->Value.pbData[n]);
    }
    _tprintf(_T("\n"));
}


BOOL PrintCertContext(PCCERT_CONTEXT pCertContext)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    __try {
        //用openssl的方式处理pCertContext->cbCertEncoded + pCertContext->pbCertEncoded。
        //经测试，这种办法有效可行正确。
        if (false) {
            const unsigned char * p = (const unsigned char *)pCertContext->pbCertEncoded;
            X509 * x509 = d2i_X509(NULL, &p, pCertContext->cbCertEncoded);
            DumpX509(x509);
            X509_free(x509);
        }

        //可以考虑根据pCertContext->hCertStore获取更多的信息。

        _tprintf(_T("证书编码类型:%d.\n"), pCertContext->dwCertEncodingType);

        DumpCertInfo(pCertContext->pCertInfo);

        // Get Issuer name size.
        if (!(dwData = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         CERT_NAME_ISSUER_FLAG,
                                         NULL,
                                         NULL,
                                         0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for issuer name.\n"));
            __leave;
        }

        // Get Issuer name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // print Issuer name.
        _tprintf(_T("颁发者: %s\n"), szName);
        LocalFree(szName);
        szName = NULL;

        // Get Subject name size.
        if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for subject name.\n"));
            __leave;
        }

        // Get subject name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Print Subject Name.
        _tprintf(_T("使用者的CN: %s\n"), szName);

        DWORD dwStrType = CERT_X500_NAME_STR;
        DWORD dwCount = CertGetNameString(pCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, NULL, 0);
        if (dwCount) {
            LPTSTR szSubjectRDN = (LPTSTR)LocalAlloc(0, dwCount * sizeof(TCHAR));
            dwCount = CertGetNameString(pCertContext,
                                        CERT_NAME_RDN_TYPE,
                                        0,
                                        &dwStrType,
                                        szSubjectRDN,
                                        dwCount);
            if (dwCount) {
                _tprintf(_T("使用者：%s\n"), szSubjectRDN);
            }

            LocalFree(szSubjectRDN);
        }

        fReturn = TRUE;
    } __finally {
        if (szName != NULL)
            LocalFree(szName);
    }

    return fReturn;
}


void DecodeCertificate(PBYTE Certificate, DWORD Length)
/*
功能：用CryptDecodeObjectEx解码PKCS#7 SignedData的ASN1结构。
*/
{
    //  Get the length needed for the decoded buffer.
    DWORD cbDecoded = NULL;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_CONTENT_INFO,//X509_NAME
                            Certificate,     // the buffer to be decoded
                            Length,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            NULL,
                            NULL,
                            &cbDecoded)) {
        //printf("The needed buffer length is %d\n", cbDecoded);
    } else {
        _ASSERTE(false);
    }

    // Allocate memory for the decoded information.
    BYTE * pbDecoded;
    if (!(pbDecoded = (BYTE *)malloc(cbDecoded))) {
        _ASSERTE(false);
    }

    // Decode the encoded buffer.
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_CONTENT_INFO,//X509_NAME
                            Certificate,     // the buffer to be decoded
                            Length,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            NULL,
                            pbDecoded,
                            &cbDecoded)) {
        CRYPT_CONTENT_INFO * content_info = (CRYPT_CONTENT_INFO *)pbDecoded;
        if (content_info) {
            printf("ObjId:%s\n", content_info->pszObjId);

            //WCHAR szSubject[1024] = {0};//d2i_X509_NAME  +  X509_NAME_oneline
            //DWORD cbSize = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            //                             &content_info->Content,
            //                             CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
            //                             szSubject,
            //                             sizeof(szSubject));
            //if (cbSize > 1) {//  If it returns one, the name is an empty string.
            //    ///printf("szSubject：%ls\n", szSubject);//内容为空。
            //} else {
            //    _ASSERTE(false);
            //}

            HCERTSTORE CertStore = NULL;
            HCRYPTMSG Msg = NULL;
            CryptQueryObject(CERT_QUERY_OBJECT_BLOB,
                             &content_info->Content,
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0,
                             NULL,
                             NULL,
                             NULL,
                             &CertStore,
                             &Msg,
                             NULL);

            PCCERT_CONTEXT PrevCertContext = NULL;
            while ((PrevCertContext = CertEnumCertificatesInStore(CertStore, PrevCertContext)) != NULL) {
                PrintCertContext(PrevCertContext);
                _tprintf(_T("\n\n\n"));
            }
        } else {
            _ASSERTE(false);
        }
    } else {
        _ASSERTE(false);
    }
}


void PrintSecurity(LPWIN_CERTIFICATE SecurityDirectory)
{
    printf("Length:%d.\r\n", SecurityDirectory->dwLength);
    printf("Revision:%d(%s).\r\n",
           SecurityDirectory->wRevision,
           GetCertRevision(SecurityDirectory->wRevision));
    printf("CertificateType:%d(%s).\r\n",
           SecurityDirectory->wCertificateType,
           GetCertificateType(SecurityDirectory->wCertificateType));

    switch (SecurityDirectory->wCertificateType) {
    case WIN_CERT_TYPE_X509://bCertificate 包含的是 X.509 证书
        _ASSERTE(false);
        break;
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA://bCertificate 包含的是 PKCS#7 SignedData 结构
    {
        //这个数据是啥结构呢？
        //以前的经验是SecurityDirectory->bCertificate里面有utf8编码。

        /*
        这里的数据可用CryptDecodeObjectEx解析不？
        这应该是ASN格式的。
        注意：数据结构CERT_ALT_NAME_ENTRY。

        这里的数据可以用openssl的函数解析，如：d2i_PKCS7等。
        参考：https://github.com/ajkhoury/CertDump.git
        */

        //经测试，这种办法有效可行正确。
        if (false) {
            unsigned char * CertData = (unsigned char *)SecurityDirectory->bCertificate;
            long CertDataLength = SecurityDirectory->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
            PKCS7 * pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&CertData, CertDataLength);
            DumpPKCS7(pkcs7);
        }

        DecodeCertificate(SecurityDirectory->bCertificate, SecurityDirectory->dwLength);

        break;
    }
    case WIN_CERT_TYPE_RESERVED_1://保留。 
        _ASSERTE(false);
        break;
    case WIN_CERT_TYPE_TS_STACK_SIGNED://终端服务器协议栈证书签名
        _ASSERTE(false);
        break;
    default:
        _ASSERTE(false);
        break;
    }

    printf("\r\n");
}


BOOL WINAPI DigestFunction(DIGEST_HANDLE refdata, PBYTE pData, DWORD dwLength)
//这个会被调用多次。
{

    return true;
}


BOOL VerifyEmbeddedSignature(IN LPCTSTR filename, OUT wchar_t * signer_file)
{
    HCATADMIN cat_admin_handle = NULL;
    if (!CryptCATAdminAcquireContext(&cat_admin_handle, NULL, 0)) {
        printf("FileName:%ls, GetLastError:%#x", filename, GetLastError());
        return FALSE;
    }

    HANDLE hFile = CreateFileW(filename,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               0,
                               NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        printf("FileName:%ls, GetLastError:%#x", filename, GetLastError());
        CryptCATAdminReleaseContext(cat_admin_handle, 0);
        return FALSE;
    }

    DWORD hash_count = 100;
    BYTE hash_data[100];
    CryptCATAdminCalcHashFromFileHandle(hFile, &hash_count, hash_data, 0);
    CloseHandle(hFile);

    wstring member_tag;
    for (DWORD dw = 0; dw < hash_count; dw++) {
        member_tag += L"0123456789ABCDEF"[(hash_data[dw] >> 4) & 0x0f];
        member_tag += L"0123456789ABCDEF"[hash_data[dw] & 0x0f];
    }

    WINTRUST_DATA wd = {0};
    HCATINFO cat_admin_info = CryptCATAdminEnumCatalogFromHash(cat_admin_handle,
                                                               hash_data,
                                                               hash_count,
                                                               0,
                                                               NULL);
    if (NULL == cat_admin_info) {
        WINTRUST_FILE_INFO wfi = {0};
        wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
        wfi.pcwszFilePath = filename;

        wd.cbStruct = sizeof(WINTRUST_DATA);
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &wfi;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.dwProvFlags = WTD_SAFER_FLAG;

        lstrcpy(signer_file, filename);
    } else {
        CATALOG_INFO ci = {0};
        CryptCATCatalogInfoFromContext(cat_admin_info, &ci, 0);

        WINTRUST_CATALOG_INFO wci = {0};
        wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
        wci.pcwszMemberFilePath = filename;
        wci.pcwszMemberTag = member_tag.c_str();
        wci.pbCalculatedFileHash = hash_data;
        wci.cbCalculatedFileHash = hash_count;

        wd.cbStruct = sizeof(WINTRUST_DATA);
        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.pCatalog = &wci;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;

        lstrcpy(signer_file, ci.wszCatalogFile);
    }

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    HRESULT hr = WinVerifyTrust(NULL, &action, &wd);
    Sleep(1);
    BOOL retval = SUCCEEDED(hr);

    if (NULL != cat_admin_info) {
        CryptCATAdminReleaseCatalogContext(cat_admin_handle, cat_admin_info, 0);
    }
    CryptCATAdminReleaseContext(cat_admin_handle, 0);
    return retval;
}


BOOL GetSignerInfo(IN WCHAR * FileName)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult = FALSE;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;

    __try {
        // Get message handle and store handle from the signed file.
        DWORD dwEncoding, dwContentType, dwFormatType;
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                   FileName,
                                   CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                   CERT_QUERY_FORMAT_FLAG_BINARY,
                                   0,
                                   &dwEncoding,
                                   &dwContentType,
                                   &dwFormatType,
                                   &hStore,
                                   &hMsg,
                                   NULL);
        if (!fResult) {
            printf("FileName:%ls, GetLastError:%#x", FileName, GetLastError());
            __leave;
        }

        // Get signer information size.
        DWORD dwSignerInfo = NULL;
        fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
        if (!fResult) {
            printf("FileName:%ls, GetLastError:%#x", FileName, GetLastError());
            __leave;
        }

        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
            printf("FileName:%ls, GetLastError:%#x", FileName, GetLastError());
            __leave;
        }

        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);
        if (!fResult) {
            printf("FileName:%ls, GetLastError:%#x", FileName, GetLastError());
            __leave;
        }

        // Search for the signer certificate in the temporary certificate store.
        CERT_INFO CertInfo;
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;
        pCertContext = CertFindCertificateInStore(hStore,
                                                  (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                                                  0,
                                                  CERT_FIND_SUBJECT_CERT,
                                                  (PVOID)&CertInfo,
                                                  NULL);
        if (!pCertContext) {
            printf("FileName:%ls, GetLastError:%#x", FileName, GetLastError());
            fResult = FALSE;
            __leave;
        }

        PrintCertContext(pCertContext);

        fResult = TRUE;
    } __finally {
        if (pSignerInfo != NULL)
            LocalFree(pSignerInfo);

        if (pCertContext != NULL)
            CertFreeCertificateContext(pCertContext);

        if (hStore != NULL)
            CertCloseStore(hStore, 0);

        if (hMsg != NULL)
            CryptMsgClose(hMsg);
    }

    return fResult;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void ParseCertificateInfo1()
{
    int Args;
    LPWSTR * Arglist = CommandLineToArgvW(GetCommandLineW(), &Args);
    LPCWSTR FileName = Arglist[2];

    wchar_t signer_file[MAX_PATH] = {0};
    if (VerifyEmbeddedSignature(FileName, signer_file)) {
        printf("%ls的签名信息所在的文件是:%ls\n", FileName, signer_file);
        if (GetSignerInfo(signer_file)) {
            printf("%ls具有合法的签名\n", FileName);
        }
    }

    LocalFree(Arglist);
}


void ParseCertificateInfo2()
/*
用系统的API解析下证书的信息，以便和自己解析的对比。

这种方式没有分析PE文件的DataDirectory。
*/
{
    int Args;
    LPWSTR * Arglist = CommandLineToArgvW(GetCommandLineW(), &Args);

    LPCWSTR FileName = Arglist[2];

    HANDLE hfile = INVALID_HANDLE_VALUE;
    LPWIN_CERTIFICATE buffer = NULL;

    __try {
        hfile = CreateFile(FileName,
                           FILE_READ_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            int x = GetLastError();
            __leave;
        }

        DWORD CertificateCount = 0;
        DWORD Indices[9] = {0};
        DWORD  IndexCount = ARRAYSIZE(Indices);
        BOOL ret = ImageEnumerateCertificates(hfile,
                                              CERT_SECTION_TYPE_ANY,
                                              &CertificateCount,
                                              Indices,
                                              IndexCount);
        if (!ret) {
            int x = GetLastError();
            __leave;
        }

        for (DWORD i = 0; i < CertificateCount; i++) {
            WIN_CERTIFICATE Certificateheader = {0};
            ret = ImageGetCertificateHeader(hfile, i, &Certificateheader);
            if (!ret) {
                int x = GetLastError();
            }

            WIN_CERTIFICATE Certificate = {0};
            DWORD RequiredLength = sizeof(WIN_CERTIFICATE);
            ret = ImageGetCertificateData(hfile, i, &Certificate, &RequiredLength);
            if (!ret) {
                int x = GetLastError();
            }

            buffer = (LPWIN_CERTIFICATE)HeapAlloc(GetProcessHeap(), 0, RequiredLength);
            _ASSERTE(buffer);

            ret = ImageGetCertificateData(hfile, i, buffer, &RequiredLength);
            _ASSERTE(ret);

            CRYPT_DATA_BLOB p7Data;
            p7Data.cbData = RequiredLength - sizeof(DWORD) - sizeof(WORD) - sizeof(WORD);
            p7Data.pbData = buffer->bCertificate;
            HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_PKCS7,
                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              NULL,
                                              0,
                                              &p7Data);
            if (hStore) {
                int count = 0;
                char szCodeSigningOID[] = szOID_PKIX_KP_CODE_SIGNING;
                // populate the key usage structure with the Code Signing OID
                CERT_ENHKEY_USAGE keyUsage;
                keyUsage.cUsageIdentifier = 1;
                keyUsage.rgpszUsageIdentifier = (LPSTR *)LocalAlloc(0, sizeof(LPSTR));
                keyUsage.rgpszUsageIdentifier[0] = &szCodeSigningOID[0];

                // Find certificates that contain the Code Signing Enhanced Key Usage
                PCCERT_CONTEXT  pCertContext = NULL;
                do {
                    pCertContext = CertFindCertificateInStore(hStore,
                                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                              CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                                              CERT_FIND_ENHKEY_USAGE,
                                                              &keyUsage,
                                                              pCertContext);
                    if (pCertContext) {
                        count++;
                        PrintCertContext(pCertContext);
                        _tprintf(_T("\n\n\n"));
                    }
                } while (pCertContext);

                if (count == 0) {
                    _tprintf(_T("No Code Signing certificates found\n"));
                }

                LocalFree(keyUsage.rgpszUsageIdentifier);
                CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
            } else {
                _tprintf(_T("CertOpenStore failed with error 0x%.8X\n"), GetLastError());
            }

            DIGEST_HANDLE DigestHandle = NULL;
            ret = ImageGetDigestStream(hfile, i, DigestFunction, DigestHandle);
            if (!ret) {
                int x = GetLastError();
            }

            HeapFree(GetProcessHeap(), 0, buffer);
        }
    } __finally {
        if (INVALID_HANDLE_VALUE != hfile) {
            CloseHandle(hfile);
        }
    }

    LocalFree(Arglist);
}


void ParseCertificateInfo3(PIMAGE_DATA_DIRECTORY DataDirectory, LPWIN_CERTIFICATE SecurityDirectory)
/*

此方式的效果类似：signtool.exe verify /pa /a /v c:\windows\notepad.exe，但比这个更强更多。

从分析PE文件的DataDirectory开始，一步一步的解析。
*/
{
    for (DWORD i = 0; i < DataDirectory->Size; ) {
        SecurityDirectory = LPWIN_CERTIFICATE((PBYTE)SecurityDirectory + i);

        printf("index:%d.\r\n", i + 1);

        PrintSecurity(SecurityDirectory);

        DWORD dwLength = SecurityDirectory->dwLength / 8;

        if (SecurityDirectory->dwLength % 8) {
            dwLength++;
        }

        i += dwLength * 8;
    }
}


void ParseCertificateInfo4(PIMAGE_DATA_DIRECTORY DataDirectory, LPWIN_CERTIFICATE SecurityDirectory)
/*
用openssl解析PE的证书。
*/
{
    unsigned char * CertData = (unsigned char *)SecurityDirectory->bCertificate;
    long CertDataLength = SecurityDirectory->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
    PKCS7 * pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&CertData, CertDataLength);
    if (NULL == pkcs7) {
        return;
    }

    DumpPKCS7(pkcs7);
}


void print_hex(const uint8_t * data, unsigned int len)
{
    unsigned int count = 0;
    unsigned int blockCount = 0;

    while (count < len) {
        printf("%02x ", data[count]);

        ++count;
        ++blockCount;

        if (blockCount == 4)
            printf("  ");

        if (blockCount == 8) {
            printf("\n");
            blockCount = 0;
        }
    }

    printf("\n");
}


void print_asn1(const asn1_tree * list, int depth)
{
    printf("d=%d, Tag: %02x, len=%d\n", depth, list->type, list->length);

    if (list->child == NULL) {
        printf("Value:\n");
        print_hex(list->data, list->length);
    } else {
        print_asn1(list->child, depth + 1);
    }

    if (list->next != NULL) {
        print_asn1(list->next, depth);
    }
}


void ParseCertificateInfo5(PIMAGE_DATA_DIRECTORY DataDirectory, LPWIN_CERTIFICATE SecurityDirectory)
/*
用ASN解析PE的证书。

仅仅测试代码。
*/
{
    unsigned char * CertData = (unsigned char *)SecurityDirectory->bCertificate;
    long CertDataLength = SecurityDirectory->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
    
    int32_t asn1_object_count = der_object_count(CertData, CertDataLength);
    if (asn1_object_count < 0) {
        fprintf(stderr, "ERROR: Could not calculate the number of Elements within the data.\n");
        return;
    }

    asn1_tree * asn1_objects = (asn1_tree *)(malloc(sizeof(asn1_tree) * asn1_object_count));
    if (asn1_objects == NULL) {
        fprintf(stderr, "ERROR: Could not allocate the memory for the ASN.1 objects.\n");
        return;
    }

    asn1_tree cms;
    if (der_decode(CertData, CertDataLength, &cms, asn1_objects, asn1_object_count) < 0) {
        fprintf(stderr, "ERROR: Could not parse the data.\n");
        return;
    }
     
    print_asn1(&cms, 0); //Dump the data

    //Since we know this is CMS data, we can try to interpret it.
    if (cms.type != ASN1_TYPE_SEQUENCE) {
        fprintf(stderr, "ERROR: The outer type is not a SEQUENCE.\n");
        return;
    }

    asn1_tree * content_type = cms.child;
    if (content_type == NULL || content_type->type != ASN1_TYPE_OBJECT_IDENTIFIER) {
        fprintf(stderr, "ERROR: No ContentType information available.\n");
        return;
    }

    asn1_tree * encrypted_data = content_type->next->child;
    if (encrypted_data == NULL || encrypted_data->type != ASN1_TYPE_SEQUENCE) {
        fprintf(stderr, "ERROR: EncryptedData not availavble.\n");
        return;
    }

    asn1_tree * cms_version = encrypted_data->child;
    if (cms_version == NULL || cms_version->type != ASN1_TYPE_INTEGER || cms_version->length != 1) {
        fprintf(stderr, "ERROR: CMSVersion not availavble.\n");
        return;
    }
    uint8_t version = cms_version->data[0];
    printf("CMSVersion: %d\n", version);

    free(asn1_objects);
}


DWORD Security(_In_ PBYTE Data, _In_ DWORD Size)
/*
参考：\win2k\trunk\private\sdktools\imagehlp\dice.cxx的FindCertificate函数。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式一：\n");
    ParseCertificateInfo1();

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_SECURITY, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Security.\r\n");
        return ret;
    }

    printf("Security Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    //ULONG size = 0;
    //PIMAGE_SECTION_HEADER FoundHeader = NULL;
    //LPWIN_CERTIFICATE SecurityDirectory = (LPWIN_CERTIFICATE)
    //    ImageDirectoryEntryToDataEx(Data,
    //                                FALSE,//自己映射的用FALSE，操作系统加载的用TRUE。 
    //                                IMAGE_DIRECTORY_ENTRY_SECURITY,
    //                                &size,
    //                                &FoundHeader);

    LPWIN_CERTIFICATE SecurityDirectory = (LPWIN_CERTIFICATE)(Data + DataDirectory.VirtualAddress);

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    //////////////////////////////////////////////////////////////////////////////////////////////

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式二：\n");
    ParseCertificateInfo2();

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式三：\n");
    ParseCertificateInfo3(&DataDirectory, SecurityDirectory);

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式四：\n");
    ParseCertificateInfo4(&DataDirectory, SecurityDirectory);

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式五：\n");
    ParseCertificateInfo5(&DataDirectory, SecurityDirectory);

    //////////////////////////////////////////////////////////////////////////////////////////////

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Security(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Security);
}

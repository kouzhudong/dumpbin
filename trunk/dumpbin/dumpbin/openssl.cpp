#include "pch.h"
#include "openssl.h"


#pragma warning(disable:4996)


//////////////////////////////////////////////////////////////////////////////////////////////////


const char * GetLnByNid(int nid)
{
    const char * ln = "有待处理";

    switch (nid) {
    case NID_rsaEncryption:
        ln = LN_rsaEncryption;
        break;
    case NID_md5WithRSAEncryption:
        ln = LN_md5WithRSAEncryption;
        break;
    case NID_sha256WithRSAEncryption:
        ln = LN_sha256WithRSAEncryption;
        break;
    case NID_sha1WithRSAEncryption:
        ln = LN_sha1WithRSAEncryption;
        break;
    case NID_sha256:
        ln = LN_sha256;
        break;
    case NID_sha1:
        ln = LN_sha1;
        break;
    default:
        break;
    }

    return ln;
}


void DumpX509(X509 * x509)
{
    long version = X509_get_version(x509);
    printf("版本:V%d.\n", version + 1);

    ASN1_INTEGER * serialNumber = X509_get_serialNumber(x509);
    printf("序列号:");
    for (int i = 0; i < serialNumber->length; i++) {
        printf("%02x", serialNumber->data[i]);
    }
    printf("\n");

    X509_NAME * issuer_name = X509_get_issuer_name(x509);
    int issuer_count = X509_NAME_entry_count(issuer_name);
    string name;
    for (int i = 0; i < issuer_count; i++) {
        X509_NAME_ENTRY * entry = X509_NAME_get_entry(issuer_name, i);
        ASN1_STRING * data = X509_NAME_ENTRY_get_data(entry);
        if (name.length()) {
            name += ", ";
        }
        name += (char *)data->data;
    }
    printf("颁发者:%s.\n", name.c_str());
    name.clear();

    X509_NAME * subject_name = X509_get_subject_name(x509);
    int subject_count = X509_NAME_entry_count(subject_name);
    for (int i = 0; i < subject_count; i++) {
        X509_NAME_ENTRY * entry = X509_NAME_get_entry(subject_name, i);
        ASN1_STRING * data = X509_NAME_ENTRY_get_data(entry);
        if (name.length()) {
            name += ", ";
        }
        name += (char *)data->data;
    }
    printf("使用者:%s.\n", name.c_str());

    const ASN1_TIME * notBefore = X509_get0_notBefore(x509);
    struct tm tm;
    int ret = ASN1_TIME_to_tm(notBefore, &tm);
    printf("有效期从：%04d年%02d月%02d日 %02d:%02d:%02d.\n",
           tm.tm_year + 1900,
           tm.tm_mon + 1,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec);

    const ASN1_TIME * notAfter = X509_get0_notAfter(x509);
    ret = ASN1_TIME_to_tm(notAfter, &tm);
    printf("到：%04d年%02d月%02d日 %02d:%02d:%02d.\n",
           tm.tm_year + 1900,
           tm.tm_mon + 1,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec);

    //////////////////////////////////////////////////////////////////////////////////////////////

    int signature_type = X509_get_signature_type(x509);

    int secbits;
    int nid; //取值，如：NID_md5WithRSAEncryption
    int pknid;//取值，如：NID_rsaEncryption 
    X509_get_signature_info(x509, &nid, &pknid, &secbits, NULL);

    printf("签名算法:%s.\n", GetLnByNid(pknid));
    printf("签名哈希算法:%s.\n", GetLnByNid(nid));

    nid = X509_get_signature_nid(x509);//这个得到的竟然和上面的不一样。
    //printf("签名哈希算法:%s.\n", GetLnByNid(nid));//但是和下面的一样。    

    const X509_ALGOR * sig_alg;
    const ASN1_BIT_STRING * sig;
    X509_get0_signature(&sig, &sig_alg, x509);

    char oid[128] = {0};//形如：1.2.840.113549.1.1.11
    OBJ_obj2txt(oid, 128, sig_alg->algorithm, 1);

    nid = OBJ_obj2nid(sig_alg->algorithm);//NID_md5WithRSAEncryption
    printf("签名算法(Signature Algorithm):%s.\n", GetLnByNid(nid));

    //printf("公钥参数:%d.\n", sig_alg->parameter->type);//这个值的字节序好像不对。

    //////////////////////////////////////////////////////////////////////////////////////////////

    int crit = 0;
    AUTHORITY_KEYID * akeyid = NULL;
    akeyid = (AUTHORITY_KEYID *)X509_get_ext_d2i(x509, NID_authority_key_identifier, &crit, NULL);
    if (akeyid) {
        printf("授权密钥标识符:");
        for (int i = 0; i < akeyid->keyid->length; i++) {
            printf("%02x", akeyid->keyid->data[i]);
        }
        printf("\n");
    }

    ASN1_OCTET_STRING * skid = NULL;
    skid = (ASN1_OCTET_STRING *)X509_get_ext_d2i(x509, NID_subject_key_identifier, &crit, NULL);
    printf("使用者密钥标识符:");
    for (int i = 0; i < skid->length; i++) {
        printf("%02x", skid->data[i]);
    }
    printf("\n");

    BASIC_CONSTRAINTS * bc;
    bc = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL);
    if (bc) {
        printf("基本约束：Subject Type=%d.", bc->ca);//这个数具体代表啥定义，有待深入。
        if (bc->pathlen) {
            printf("Basic Constraints:");
            for (int i = 0; i < bc->pathlen->length; i++) {
                printf("%02x", bc->pathlen->data[i]);
            }
            printf("\n");
        } else {
            printf("Path Length Constraint=None.\n");
        }
    }

    //NID_key_usage.密钥用途。
    //NID_subject_alt_name.域名。

    //////////////////////////////////////////////////////////////////////////////////////////////

    const EVP_MD * fprint_type = EVP_sha1();
    unsigned char fprint[EVP_MAX_MD_SIZE] = {0};
    unsigned int fprint_size = 0;

    X509_digest(x509, fprint_type, fprint, &fprint_size);

    printf("指纹:");
    for (unsigned int i = 0; i < fprint_size; i++) {
        printf("%02x", fprint[i]);
    }
    printf("\n");

    //////////////////////////////////////////////////////////////////////////////////////////////

    X509_PUBKEY * PUBKEY = X509_get_X509_PUBKEY(x509);
    //EVP_PKEY * X509_get_pubkey(X509 * x509);
    ASN1_BIT_STRING * pubkey_bitstr = X509_get0_pubkey_bitstr(x509);

    size_t          publen = 0;
    unsigned char * pub = NULL;
    EVP_PKEY * pkey = X509_get0_pubkey(x509);
    int keyid = EVP_PKEY_id(pkey); //EVP_PKEY_RSA

    switch (keyid) {
    case EVP_PKEY_RSA:
        printf("公钥类型:RSA\n");
        break;
    case EVP_PKEY_DSA:
        printf("公钥类型:DSA\n");
        break;
    default:
        printf("公钥类型:有待补充\n");
        break;
    }

    printf("公钥长度:%d bits\n", EVP_PKEY_bits(pkey));

    int len = i2d_X509_PUBKEY(PUBKEY, NULL);
    //char * key = (char *)HeapAlloc(GetProcessHeap(), 0, len);
    //char * key = new char[len]();
    char * key = NULL;//这里获取的内容好像不对。
    len = i2d_X509_PUBKEY(PUBKEY, (unsigned char **)&key);

    const unsigned char * pp = NULL;
    int pklen;
    //EC_KEY * eckey = NULL;
    X509_ALGOR * palg;
    const void * pval;
    int ptype;

    X509_PUBKEY_get0_param(NULL, &pp, &pklen, &palg, PUBKEY);
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);
    //d2i_X509_ALGOR(&palg, &pp, pklen);//这个会导致进程退出异常。

    //printf("公钥参数:%d.\n", ptype);//这个值的字节序好像不对。

    //HeapFree(GetProcessHeap(), 0, key);
    //delete [] key;
    OPENSSL_free(key);

    //////////////////////////////////////////////////////////////////////////////////////////////    

    EVP_PKEY * pubkey = X509_get_pubkey(x509);
    unsigned char tem[1024] = {0};
    unsigned char * p = tem;
    len = i2d_PublicKey(pubkey, &p);

    printf("公钥:");
    for (int i = 0; i < len; i++) {
        unsigned char t = tem[i];
        printf("%02x", t);
    }
    printf("\n");

    RSA * rsa = EVP_PKEY_get1_RSA(pubkey);
    char * Modulus = BN_bn2hex(RSA_get0_n(rsa));
    char * Exponent = BN_bn2hex(RSA_get0_e(rsa));

    printf("Modulus:%s\n", Modulus);
    printf("Exponent:%s\n", Exponent);

    //printf("公钥长度:%d bits\n", RSA_size(rsa) * 8);

    OPENSSL_free(Modulus);
    OPENSSL_free(Exponent);
    RSA_free(rsa);
}


void DumpPKCS7(PKCS7 * pkcs7)
{
    char       name[10000];
    int ret = OBJ_obj2txt(name, 1000, pkcs7->type, 0);
    printf("type : %s \n", name);

    int type = OBJ_obj2nid(pkcs7->type);

    STACK_OF(X509) * X509Certs = NULL;
    STACK_OF(X509_CRL) * X509Crls = NULL;

    switch (type) {
    case NID_pkcs7_signed:
        if (pkcs7->d.sign != NULL) {
            X509Certs = pkcs7->d.sign->cert;
            X509Crls = pkcs7->d.sign->crl;
        }
        break;
    case NID_pkcs7_signedAndEnveloped:
        if (pkcs7->d.signed_and_enveloped != NULL) {
            X509Certs = pkcs7->d.signed_and_enveloped->cert;
            X509Crls = pkcs7->d.signed_and_enveloped->crl;
        }
        break;
    default:
        return;
        break;
    }

    for (int CertIndex = 0; CertIndex < sk_X509_num(X509Certs); CertIndex++) {
        X509 * X509Cert = sk_X509_value(X509Certs, CertIndex);

        printf("第:%d个证书的信息：\n", CertIndex + 1);

        DumpX509(X509Cert);

        printf("\n\n\n");
    }
}


//int test()
//{
//    OPENSSL_die("Voluntary abort", __FILE__, __LINE__);
//    return 0;
//}


//////////////////////////////////////////////////////////////////////////////////////////////////

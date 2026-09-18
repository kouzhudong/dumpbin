#include "pch.h"
#include "openssl.h"
#include <vector>


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
    std::string name;
    for (int i = 0; i < issuer_count; i++) {
        X509_NAME_ENTRY * entry = X509_NAME_get_entry(issuer_name, i);
        ASN1_STRING * data = X509_NAME_ENTRY_get_data(entry);
        if (name.length()) {
            name += ", ";
        }
        //ASN1 字符串不保证以 0 结尾，必须按长度取。
        name.append((const char *)ASN1_STRING_get0_data(data), ASN1_STRING_length(data));
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
        name.append((const char *)ASN1_STRING_get0_data(data), ASN1_STRING_length(data));
    }
    printf("使用者:%s.\n", name.c_str());//这是UTF8编码。汉字会显示乱码，需转换。

    struct tm tm = {0};
    const ASN1_TIME * notBefore = X509_get0_notBefore(x509);
    if (ASN1_TIME_to_tm(notBefore, &tm) == 1) {
        printf("有效期从：%04d年%02d月%02d日 %02d:%02d:%02d.\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
        printf("有效期从：无法解析.\n");
    }

    const ASN1_TIME * notAfter = X509_get0_notAfter(x509);
    if (ASN1_TIME_to_tm(notAfter, &tm) == 1) {
        printf("到：%04d年%02d月%02d日 %02d:%02d:%02d.\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
        printf("到：无法解析.\n");
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

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
        if (akeyid->keyid != NULL) {
            printf("授权密钥标识符:");
            for (int i = 0; i < akeyid->keyid->length; i++) {
                printf("%02x", akeyid->keyid->data[i]);
            }
            printf("\n");
        }

        AUTHORITY_KEYID_free(akeyid);
    }

    ASN1_OCTET_STRING * skid = NULL;
    skid = (ASN1_OCTET_STRING *)X509_get_ext_d2i(x509, NID_subject_key_identifier, &crit, NULL);
    if (skid) {
        printf("使用者密钥标识符:");
        for (int i = 0; i < skid->length; i++) {
            printf("%02x", skid->data[i]);
        }
        printf("\n");

        ASN1_OCTET_STRING_free(skid);
    }

    BASIC_CONSTRAINTS * bc = NULL;
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

        BASIC_CONSTRAINTS_free(bc);
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
    EVP_PKEY * pkey = X509_get0_pubkey(x509);//借用的引用，不需要释放。
    if (pkey == NULL) {
        printf("公钥无效.\n");
        return;
    }

    int keyid = EVP_PKEY_id(pkey);//EVP_PKEY_RSA
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

    //i2d_X509_PUBKEY 会自己分配内存(结果要用 OPENSSL_free 释放)，先算长度只是为了确认能编码。
    int len = i2d_X509_PUBKEY(PUBKEY, NULL);
    if (len > 0) {
        unsigned char * key = NULL;
        len = i2d_X509_PUBKEY(PUBKEY, &key);
        if (len > 0) {
            printf("公钥(X509_PUBKEY):");
            for (int i = 0; i < len; i++) {
                printf("%02x", key[i]);
            }
            printf("\n");
        }

        OPENSSL_free(key);
    }

    const unsigned char * pp = NULL;
    int pklen = 0;
    X509_ALGOR * palg = NULL;
    const void * pval = NULL;
    int ptype = 0;

    X509_PUBKEY_get0_param(NULL, &pp, &pklen, &palg, PUBKEY);
    if (palg != NULL) {
        X509_ALGOR_get0(NULL, &ptype, &pval, palg);
    }
    //d2i_X509_ALGOR(&palg, &pp, pklen);//这个会导致进程退出异常。

    //printf("公钥参数:%d.\n", ptype);//这个值的字节序好像不对。

    //////////////////////////////////////////////////////////////////////////////////////////////

    //公钥的 DER 长度事先不知道(RSA 8192 位就超过 1KB)，必须先取长度再分配，不能用固定大小的栈数组。
    len = i2d_PublicKey(pkey, NULL);
    if (len > 0) {
        std::vector<unsigned char> buffer((SIZE_T)len, 0);
        unsigned char * p = buffer.data();
        int written = i2d_PublicKey(pkey, &p);
        if (written > 0 && written <= len) {
            printf("公钥:");
            for (int i = 0; i < written; i++) {
                printf("%02x", buffer[(SIZE_T)i]);
            }
            printf("\n");
        }
    }

    if (keyid == EVP_PKEY_RSA) {
        BIGNUM * n = NULL;
        BIGNUM * e = NULL;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1 && n != NULL) {
            char * Modulus = BN_bn2hex(n);
            printf("Modulus:%s\n", Modulus != NULL ? Modulus : "(无)");
            OPENSSL_free(Modulus);
        }

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1 && e != NULL) {
            char * Exponent = BN_bn2hex(e);
            printf("Exponent:%s\n", Exponent != NULL ? Exponent : "(无)");
            OPENSSL_free(Exponent);
        }

        BN_free(n);
        BN_free(e);
    }

    //printf("公钥长度:%d bits\n", RSA_size(rsa) * 8);
}


void DumpPKCS7(PKCS7 * pkcs7)
{
    char name[10000] = {0};
    OBJ_obj2txt(name, _countof(name), pkcs7->type, 0);
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

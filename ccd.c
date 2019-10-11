/* Add your header comment here */
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
#include <stdlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

SQLITE_EXTENSION_INIT1

typedef unsigned char UCHAR;
typedef char CHAR;
typedef UCHAR * (*hash_function_t)(const UCHAR *in);

static char hex[] = "0123456789abcdef";

static inline void digit(unsigned char b, UCHAR **dest) {
    assert(b<=15);
    **dest = hex[b];
    *dest += 1;
}
static inline void byte2hex(unsigned char b, UCHAR **dest) {
    digit(b/16, dest);
    digit(b%16, dest);
}

void xStep(sqlite3_context *context, int argCount, sqlite3_value **args) {
    hash_function_t hash = (hash_function_t)sqlite3_user_data(context);
    const UCHAR *input = (const UCHAR *)sqlite3_value_text(args[0]);
    const UCHAR *output = hash(input);
    sqlite3_result_text(context, (CHAR *)output, -1, sqlite3_free);
}

UCHAR *md2(const UCHAR *in) {
    size_t digestSize = CC_MD5_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD2_CTX ctx;
    CC_MD2_Init(&ctx);
    CC_MD2_Update(&ctx, in, strlen((const CHAR *)in));
    CC_MD2_Final((UCHAR *)digest, &ctx);
#pragma clang diagnostic pop
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *md4(const UCHAR *in) {
    size_t digestSize = CC_MD5_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD4_CTX ctx;
    CC_MD4_Init(&ctx);
    CC_MD4_Update(&ctx, in, strlen((const CHAR *)in));
    CC_MD4_Final((UCHAR *)digest, &ctx);
#pragma clang diagnostic pop
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *md5(const UCHAR *in) {
    size_t digestSize = CC_MD5_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_MD5_CTX ctx;
    CC_MD5_Init(&ctx);
    CC_MD5_Update(&ctx, in, strlen((const CHAR *)in));
    CC_MD5_Final((UCHAR *)digest, &ctx);
#pragma clang diagnostic pop
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *sha1(const UCHAR *in) {
    size_t digestSize = CC_SHA1_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, in, strlen((const CHAR *)in));
    CC_SHA1_Final((UCHAR *)digest, &ctx);
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *sha224(const UCHAR *in) {
    size_t digestSize = CC_SHA224_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
    CC_SHA256_CTX ctx;
    CC_SHA224_Init(&ctx);
    CC_SHA224_Update(&ctx, in, strlen((const CHAR *)in));
    CC_SHA224_Final((UCHAR *)digest, &ctx);
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *sha256(const UCHAR *in) {
    size_t digestSize = CC_SHA256_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, in, strlen((const CHAR *)in));
    CC_SHA256_Final((UCHAR *)digest, &ctx);
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *sha384(const UCHAR *in) {
    size_t digestSize = CC_SHA384_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
    CC_SHA512_CTX ctx;
    CC_SHA384_Init(&ctx);
    CC_SHA384_Update(&ctx, in, strlen((const CHAR *)in));
    CC_SHA384_Final((UCHAR *)digest, &ctx);
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}

UCHAR *sha512(const UCHAR *in) {
    size_t digestSize = CC_SHA512_DIGEST_LENGTH;
    UCHAR *digest = sqlite3_malloc(digestSize);
    size_t bytesRead;
    CC_SHA512_CTX ctx;
    CC_SHA512_Init(&ctx);
    CC_SHA512_Update(&ctx, in, strlen((const CHAR *)in));
    CC_SHA512_Final((UCHAR *)digest, &ctx);
    size_t strSize = (digestSize * 2) + 1;
    UCHAR *string = sqlite3_malloc(strSize);
    UCHAR *temp = string;
    for (int i = 0; i < digestSize; i++) {
        byte2hex(digest[i], &temp);
    }
    sqlite3_free(digest);
    *temp = 0;
    return string;
}


#ifdef _WIN32
__declspec(dllexport)
#endif
/* TODO: Change the entry point name so that "extension" is replaced by
** text derived from the shared library filename as follows:  Copy every
** ASCII alphabetic character from the filename after the last "/" through
** the next following ".", converting each character to lowercase, and
** discarding the first three characters if they are "lib".
*/
int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
    int rc = SQLITE_OK;
    SQLITE_EXTENSION_INIT2(pApi);
//    sqlite3_create_function_v2(db, "md2", 1, SQLITE_UTF8, md2, xStep, NULL, NULL, NULL);
//    sqlite3_create_function_v2(db, "md4", 1, SQLITE_UTF8, md4, xStep, NULL, NULL, NULL);
    sqlite3_create_function_v2(db, "md5", 1, SQLITE_UTF8, md5, xStep, NULL, NULL, NULL);
//    sqlite3_create_function_v2(db, "sha1", 1, SQLITE_UTF8, sha1, xStep, NULL, NULL, NULL);
//    sqlite3_create_function_v2(db, "sha224", 1, SQLITE_UTF8, sha224, xStep, NULL, NULL, NULL);
    sqlite3_create_function_v2(db, "sha256", 1, SQLITE_UTF8, sha256, xStep, NULL, NULL, NULL);
//    sqlite3_create_function_v2(db, "sha384", 1, SQLITE_UTF8, sha384, xStep, NULL, NULL, NULL);
    sqlite3_create_function_v2(db, "sha512", 1, SQLITE_UTF8, sha512, xStep, NULL, NULL, NULL);
    return rc;
}


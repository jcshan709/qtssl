#include "qtssl.h"
#include <QDebug>
#include "openssl/sha.h"
#include "openssl/md5.h"

QByteArray encrypt::sha256(const QByteArray &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, data.size());
    SHA256_Final(hash, &ctx);
    return QByteArray::fromRawData((char*)hash, SHA256_DIGEST_LENGTH).toHex();
}

QByteArray encrypt::sha1(const QByteArray &data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, data.size());
    SHA1_Final(hash, &ctx);
    return QByteArray::fromRawData((char*)hash, SHA_DIGEST_LENGTH).toHex();
}

QByteArray encrypt::sha512(const QByteArray &data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data, data.size());
    SHA512_Final(hash, &ctx);
    return QByteArray::fromRawData((char*)hash, SHA512_DIGEST_LENGTH).toHex();
}

QByteArray encrypt::md5(const QByteArray &data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, data.size());
    MD5_Final(hash, &ctx);
    return QByteArray::fromRawData((char*)hash, MD5_DIGEST_LENGTH).toHex();
}

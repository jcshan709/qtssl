#ifndef QTSSL_H
#define QTSSL_H

#include "qtssl_global.h"
#include <QString>
#include <QByteArray>
#define DECL_ENCRYPT_FUNC(name) QByteArray QTSSL_EXPORT name (const QByteArray &data);

namespace encrypt {
    DECL_ENCRYPT_FUNC(sha256);
    DECL_ENCRYPT_FUNC(sha1);
    DECL_ENCRYPT_FUNC(sha512);
    DECL_ENCRYPT_FUNC(md5);
}

#endif // QTSSL_H

#ifndef QTSSL_GLOBAL_H
#define QTSSL_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(QTSSL_LIBRARY)
#  define QTSSL_EXPORT Q_DECL_EXPORT
#else
#  define QTSSL_EXPORT Q_DECL_IMPORT
#endif

#endif // QTSSL_GLOBAL_H

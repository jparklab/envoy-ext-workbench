#pragma once

// Small helpers over MIT Kerberos, which is built from source and linked
// statically into the module (@workbench//third_party/mit_krb5).

#include <krb5/krb5.h>

#include <string>

namespace MssqlProxy {

// This thread's Kerberos context, created on first use and freed when the
// thread ends: contexts are not shared between threads. nullptr (error set)
// when it can't be created, e.g. a broken krb5.conf.
krb5_context threadKrb5Context(std::string& error);

// The message for code, e.g. "Decrypt integrity check failed".
std::string krb5Message(krb5_context context, krb5_error_code code);

// Whether the keytab file can be read and has keys; error set otherwise.
bool checkKeytab(const std::string& path, std::string& error);

} // namespace MssqlProxy

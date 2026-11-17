#pragma once

// MIT Kerberos (libkrb5), loaded at run time with dlopen: the module links no
// Kerberos library, so it loads on hosts without one and only needs libkrb5
// when Kerberos is configured. Compiled against the build host's headers
// (@workbench//third_party/mit_krb5:headers); libkrb5.so.3's ABI is stable.

#include <krb5/krb5.h>

#include <string>

namespace MssqlProxy {

#define MSSQL_PROXY_KRB5_FUNCTIONS(X)                                                              \
  X(krb5_init_context)                                                                             \
  X(krb5_free_context)                                                                             \
  X(krb5_get_error_message)                                                                        \
  X(krb5_free_error_message)                                                                       \
  X(krb5_kt_resolve)                                                                               \
  X(krb5_kt_close)                                                                                 \
  X(krb5_kt_start_seq_get)                                                                         \
  X(krb5_kt_next_entry)                                                                            \
  X(krb5_kt_end_seq_get)                                                                           \
  X(krb5_free_keytab_entry_contents)                                                               \
  X(krb5_decode_ticket)                                                                            \
  X(krb5_free_ticket)                                                                              \
  X(krb5_server_decrypt_ticket_keytab)                                                             \
  X(krb5_c_decrypt)                                                                                \
  X(krb5_unparse_name)                                                                             \
  X(krb5_free_unparsed_name)                                                                       \
  X(krb5_parse_name)                                                                               \
  X(krb5_free_principal)                                                                           \
  X(krb5_cc_resolve)                                                                               \
  X(krb5_cc_close)                                                                                 \
  X(krb5_cc_get_principal)                                                                         \
  X(krb5_get_credentials)                                                                          \
  X(krb5_free_creds)                                                                               \
  X(krb5_auth_con_init)                                                                            \
  X(krb5_auth_con_free)                                                                            \
  X(krb5_mk_req_extended)                                                                          \
  X(krb5_free_data_contents)

struct Krb5Api {
#define MSSQL_PROXY_KRB5_MEMBER(name) decltype(&::name) name = nullptr;
  MSSQL_PROXY_KRB5_FUNCTIONS(MSSQL_PROXY_KRB5_MEMBER)
#undef MSSQL_PROXY_KRB5_MEMBER

  // The message for code, e.g. "Decrypt integrity check failed".
  std::string message(krb5_context context, krb5_error_code code) const;
};

// libkrb5.so.3, loaded once per process. nullptr (error set) when it can't be
// loaded or lacks a function.
const Krb5Api* loadKrb5(std::string& error);

} // namespace MssqlProxy

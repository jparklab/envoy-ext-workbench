#include "krb5_util.h"

#include <format>

namespace MssqlProxy {

krb5_context threadKrb5Context(std::string& error) {
  struct Holder {
    krb5_context context = nullptr;
    ~Holder() {
      if (context != nullptr) {
        krb5_free_context(context);
      }
    }
  };
  thread_local Holder holder;
  if (holder.context == nullptr) {
    if (krb5_error_code code = krb5_init_context(&holder.context)) {
      error = std::format("cannot create a Kerberos context (error {})", code);
      holder.context = nullptr;
    }
  }
  return holder.context;
}

std::string krb5Message(krb5_context context, krb5_error_code code) {
  const char* text = krb5_get_error_message(context, code);
  std::string out = text != nullptr ? text : std::format("Kerberos error {}", code);
  krb5_free_error_message(context, text);
  return out;
}

bool checkKeytab(const std::string& path, std::string& error) {
  krb5_context ctx = threadKrb5Context(error);
  if (ctx == nullptr) {
    return false;
  }
  const std::string name = "FILE:" + path;
  krb5_keytab kt = nullptr;
  if (krb5_error_code code = krb5_kt_resolve(ctx, name.c_str(), &kt)) {
    error = std::format("keytab {}: {}", path, krb5Message(ctx, code));
    return false;
  }
  krb5_kt_cursor cursor;
  size_t keys = 0;
  krb5_error_code code = krb5_kt_start_seq_get(ctx, kt, &cursor);
  if (code == 0) {
    krb5_keytab_entry entry;
    while (krb5_kt_next_entry(ctx, kt, &entry, &cursor) == 0) {
      ++keys;
      krb5_free_keytab_entry_contents(ctx, &entry);
    }
    krb5_kt_end_seq_get(ctx, kt, &cursor);
  }
  krb5_kt_close(ctx, kt);
  if (code != 0) {
    error = std::format("keytab {}: {}", path, krb5Message(ctx, code));
    return false;
  }
  if (keys == 0) {
    error = std::format("keytab {} has no keys", path);
    return false;
  }
  return true;
}

} // namespace MssqlProxy

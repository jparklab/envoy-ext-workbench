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

} // namespace MssqlProxy

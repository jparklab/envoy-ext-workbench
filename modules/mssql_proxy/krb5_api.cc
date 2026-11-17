#include "krb5_api.h"

#include <dlfcn.h>

#include <format>
#include <mutex>

namespace MssqlProxy {

std::string Krb5Api::message(krb5_context context, krb5_error_code code) const {
  const char* text = krb5_get_error_message(context, code);
  std::string out = text != nullptr ? text : std::format("Kerberos error {}", code);
  krb5_free_error_message(context, text);
  return out;
}

const Krb5Api* loadKrb5(std::string& error) {
  static std::once_flag once;
  static const Krb5Api* api = nullptr;
  static std::string load_error;
  std::call_once(once, [] {
    // Never closed: the library stays loaded for the life of the process.
    void* lib = dlopen("libkrb5.so.3", RTLD_NOW | RTLD_LOCAL);
    if (lib == nullptr) {
      load_error = std::format("cannot load libkrb5.so.3 (MIT Kerberos): {}", dlerror());
      return;
    }
    auto* loaded = new Krb5Api();
#define MSSQL_PROXY_KRB5_LOAD(name)                                                                \
  loaded->name = reinterpret_cast<decltype(&::name)>(dlsym(lib, #name));                           \
  if (loaded->name == nullptr) {                                                                   \
    load_error = "libkrb5.so.3 lacks " #name;                                                      \
    delete loaded;                                                                                 \
    return;                                                                                        \
  }
    MSSQL_PROXY_KRB5_FUNCTIONS(MSSQL_PROXY_KRB5_LOAD)
#undef MSSQL_PROXY_KRB5_LOAD
    api = loaded;
  });
  if (api == nullptr) {
    error = load_error;
  }
  return api;
}

} // namespace MssqlProxy

// LD_PRELOAD shim for the AD terminate test: takes the delegation request
// (GSS_C_DELEG_FLAG) out of every gss_init_sec_context call of the process.
// ODBC Driver 17 on Linux asks for delegation on its own (req_flags 0x3, mutual
// and delegation), so with a forwardable TGT it forwards it to every server it
// logs in to. With this shim the same real driver, TDS login included, is a
// client that forwards nothing, which is what makes the proxy use S4U2Proxy
// (the TGT is still forwardable, so the service ticket is usable as evidence).
// Everything else is passed to MIT's own function.
//
//   gcc -shared -fPIC -o gss_nodeleg_shim.so gss_nodeleg_shim.c -ldl
//   LD_PRELOAD=./gss_nodeleg_shim.so isql -k "..."
#define _GNU_SOURCE
#include <dlfcn.h>
#include <gssapi/gssapi.h>

OM_uint32 gss_init_sec_context(OM_uint32* minor, gss_cred_id_t cred, gss_ctx_id_t* context,
                               gss_name_t target, gss_OID mech, OM_uint32 req_flags,
                               OM_uint32 time_req, gss_channel_bindings_t bindings,
                               gss_buffer_t input, gss_OID* actual_mech, gss_buffer_t output,
                               OM_uint32* ret_flags, OM_uint32* time_rec) {
  typedef OM_uint32 (*Fn)(OM_uint32*, gss_cred_id_t, gss_ctx_id_t*, gss_name_t, gss_OID, OM_uint32,
                          OM_uint32, gss_channel_bindings_t, gss_buffer_t, gss_OID*, gss_buffer_t,
                          OM_uint32*, OM_uint32*);
  static Fn real;
  if (real == NULL) {
    real = (Fn)dlsym(RTLD_NEXT, "gss_init_sec_context");
  }
  if (real == NULL) {
    // The ODBC driver is dlopen'ed (by unixODBC), and so is its libgssapi:
    // it is not in the global scope RTLD_NEXT searches.
    void* lib = dlopen("libgssapi_krb5.so.2", RTLD_NOW | RTLD_NOLOAD);
    if (lib != NULL) {
      real = (Fn)dlsym(lib, "gss_init_sec_context");
    }
  }
  if (real == NULL) {
    *minor = 0;
    return GSS_S_FAILURE;
  }
  return real(minor, cred, context, target, mech, req_flags & ~(OM_uint32)GSS_C_DELEG_FLAG,
              time_req, bindings, input, actual_mech, output, ret_flags, time_rec);
}

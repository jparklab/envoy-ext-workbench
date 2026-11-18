#include "kerberos_terminate.h"

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include <sys/stat.h>

#include <atomic>
#include <ctime>
#include <format>
#include <string_view>
#include <utility>
#include <vector>

#include "gss_token.h"
#include "krb5_util.h"

namespace MssqlProxy {

struct GssTerminator::Creds {
  gss_cred_id_t acceptor = GSS_C_NO_CREDENTIAL;
  gss_cred_id_t initiator = GSS_C_NO_CREDENTIAL; // service_account only.
  // delegate with a principal named: a handle that keeps the acceptor's
  // MEMORY keytab alive (MIT frees it when the last handle closes).
  krb5_keytab memory_keytab = nullptr;

  ~Creds() {
    OM_uint32 minor;
    gss_release_cred(&minor, &acceptor);
    gss_release_cred(&minor, &initiator);
    if (memory_keytab != nullptr) {
      krb5_context context = nullptr;
      if (krb5_init_context(&context) == 0) {
        krb5_kt_close(context, memory_keytab);
        krb5_free_context(context);
      }
    }
  }
};

namespace {

// GSS major and minor status as text, e.g. "Unspecified GSS failure: Server
// not found in Kerberos database".
std::string gssMessage(OM_uint32 major, OM_uint32 minor, gss_OID mech) {
  std::string out;
  auto append = [&](OM_uint32 code, int type) {
    OM_uint32 context = 0;
    do {
      OM_uint32 ignored;
      gss_buffer_desc text = GSS_C_EMPTY_BUFFER;
      if (gss_display_status(&ignored, code, type, mech, &context, &text) != GSS_S_COMPLETE) {
        break;
      }
      if (!out.empty()) {
        out += ": ";
      }
      out.append(static_cast<const char*>(text.value), text.length);
      gss_release_buffer(&ignored, &text);
    } while (context != 0);
  };
  append(major, GSS_C_GSS_CODE);
  if (minor != 0) {
    append(minor, GSS_C_MECH_CODE);
  }
  return out;
}

gss_buffer_desc bufferOf(std::string_view s) { return {s.size(), const_cast<char*>(s.data())}; }

// Moves a GSS buffer's contents into a string and releases it.
std::string take(gss_buffer_desc& buffer) {
  std::string out(static_cast<const char*>(buffer.value), buffer.length);
  OM_uint32 minor;
  gss_release_buffer(&minor, &buffer);
  return out;
}

// Channel bindings with application data only (addresses unspecified), as
// Windows builds them.
class Bindings {
public:
  explicit Bindings(std::string_view application_data) {
    if (!application_data.empty()) {
      bindings_.application_data = bufferOf(application_data);
    }
  }
  gss_channel_bindings_t get() {
    return bindings_.application_data.length == 0 ? GSS_C_NO_CHANNEL_BINDINGS : &bindings_;
  }

private:
  gss_channel_bindings_struct bindings_{};
};

gss_cred_id_t acquire(gss_name_t name, gss_cred_usage_t usage,
                      const std::vector<std::pair<const char*, std::string>>& store,
                      std::string& error) {
  std::vector<gss_key_value_element_desc> elements;
  for (const auto& [key, value] : store) {
    elements.push_back({key, value.c_str()});
  }
  gss_key_value_set_desc set{static_cast<OM_uint32>(elements.size()), elements.data()};
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  OM_uint32 minor = 0;
  const OM_uint32 major = gss_acquire_cred_from(&minor, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                                usage, &set, &cred, nullptr, nullptr);
  if (GSS_ERROR(major)) {
    error = gssMessage(major, minor, GSS_C_NO_OID);
    return GSS_C_NO_CREDENTIAL;
  }
  return cred;
}

// The proxy's TGT is renewed when it has less than this left (seconds).
constexpr int64_t kRenewBefore = 600;

// A memory ccache name of its own per terminator.
std::string memoryCcache() {
  static std::atomic<uint64_t> next{1};
  return std::format("MEMORY:mssql_proxy_{}", next++);
}

std::string memoryKeytab() {
  static std::atomic<uint64_t> next{1};
  return std::format("MEMORY:mssql_proxy_kt_{}", next++);
}

// Changes when the "FILE:<path>" keytab is replaced or rewritten.
std::string fileStamp(const std::string& keytab) {
  struct stat st{};
  if (stat(keytab.substr(std::string_view("FILE:").size()).c_str(), &st) != 0) {
    return "?";
  }
  return std::format("{}.{}.{}", st.st_size, st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
}

// Empties the in-memory keytab, then copies into it the entries of principal
// (when not null) from the keytab source, then all those of the keytab rest.
bool fillAcceptorKeytab(krb5_context ctx, const std::string& memory, const std::string& source,
                        krb5_principal principal, const std::string& rest, std::string& error) {
  krb5_keytab target = nullptr;
  if (krb5_error_code code = krb5_kt_resolve(ctx, memory.c_str(), &target)) {
    error = "acceptor keytab: " + krb5Message(ctx, code);
    return false;
  }
  auto each = [&](const std::string& name, auto&& visit) -> krb5_error_code {
    krb5_keytab kt = nullptr;
    krb5_error_code code = krb5_kt_resolve(ctx, name.c_str(), &kt);
    krb5_kt_cursor cursor;
    if (code == 0 && (code = krb5_kt_start_seq_get(ctx, kt, &cursor)) == 0) {
      krb5_keytab_entry entry;
      while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
        visit(entry);
        krb5_free_keytab_entry_contents(ctx, &entry);
      }
      krb5_kt_end_seq_get(ctx, kt, &cursor);
      if (code == KRB5_KT_END) {
        code = 0;
      }
    }
    if (kt != nullptr) {
      krb5_kt_close(ctx, kt);
    }
    return code;
  };
  std::vector<krb5_keytab_entry> old;
  krb5_error_code code = each(memory, [&](krb5_keytab_entry& e) {
    krb5_keytab_entry copy = e;
    krb5_copy_principal(ctx, e.principal, &copy.principal);
    krb5_copy_keyblock_contents(ctx, &e.key, &copy.key);
    old.push_back(copy);
  });
  for (krb5_keytab_entry& e : old) {
    krb5_kt_remove_entry(ctx, target, &e);
    krb5_free_keytab_entry_contents(ctx, &e);
  }
  // A memory keytab lists the entry added last first, and the principal's
  // keys must come first.
  auto add = [&](krb5_keytab_entry& e) { krb5_kt_add_entry(ctx, target, &e); };
  if (code == 0) {
    code = each(rest, add);
  }
  if (code == 0 && principal != nullptr) {
    code = each(source, [&](krb5_keytab_entry& e) {
      if (krb5_principal_compare(ctx, e.principal, principal)) {
        add(e);
      }
    });
  }
  krb5_kt_close(ctx, target);
  if (code != 0) {
    error = "acceptor keytab: " + krb5Message(ctx, code);
    return false;
  }
  return true;
}

class GssExchange : public KerberosExchange {
public:
  GssExchange(std::shared_ptr<const GssTerminator> terminator, const GssTerminator::Creds& creds,
              bool delegate)
      : terminator_(std::move(terminator)), creds_(creds), delegate_(delegate) {}

  ~GssExchange() override {
    OM_uint32 minor;
    gss_delete_sec_context(&minor, &accept_context_, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &init_context_, GSS_C_NO_BUFFER);
    gss_release_cred(&minor, &delegated_);
    gss_release_name(&minor, &target_);
  }

  Step accept(std::string_view token, std::string_view binding) override {
    Step out;
    if (terminator_->needsProxyTgt() && !terminator_->ensureProxyTgt(tgt_error_)) {
      // Only constrained delegation needs it; a forwarded TGT still works.
      tgt_error_ = "the proxy's own TGT: " + tgt_error_;
    } else {
      tgt_error_.clear();
    }
    gss_buffer_desc input = bufferOf(token);
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_name_t source = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    gss_cred_id_t delegated = GSS_C_NO_CREDENTIAL;
    Bindings bindings(binding);
    OM_uint32 minor = 0;
    const OM_uint32 major =
        gss_accept_sec_context(&minor, &accept_context_, creds_.acceptor, &input, bindings.get(),
                               &source, &mech, &output, nullptr, nullptr, &delegated);
    out.token = take(output);
    if (delegated != GSS_C_NO_CREDENTIAL) {
      OM_uint32 ignored;
      gss_release_cred(&ignored, &delegated_);
      delegated_ = delegated;
    }
    if (GSS_ERROR(major)) {
      out.error = gssMessage(major, minor, mech);
    } else if ((major & GSS_S_CONTINUE_NEEDED) == 0) {
      out.complete = true;
      gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
      const OM_uint32 named = gss_display_name(&minor, source, &name, nullptr);
      if (GSS_ERROR(named)) {
        out.complete = false;
        out.error = "client name: " + gssMessage(named, minor, GSS_C_NO_OID);
      } else {
        principal_ = take(name);
      }
    }
    OM_uint32 ignored;
    gss_release_name(&ignored, &source);
    return out;
  }

  std::string clientPrincipal() const override { return principal_; }

  Step initiate(std::string_view token, const std::string& spn,
                std::string_view binding) override {
    Step out;
    const bool first = init_context_ == GSS_C_NO_CONTEXT;
    if (first) {
      init_cred_ = delegate_ ? delegated_ : creds_.initiator;
      if (delegate_ && delegated_ == GSS_C_NO_CREDENTIAL) {
        out.error = "the client's credentials can't be delegated: it forwarded no TGT, and "
                    "its ticket can't serve for constrained delegation (not forwardable)";
        return out;
      }
      gss_buffer_desc name = bufferOf(spn);
      OM_uint32 minor = 0;
      const OM_uint32 major =
          gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &target_);
      if (GSS_ERROR(major)) {
        out.error = std::format("SPN {}: {}", spn, gssMessage(major, minor, GSS_C_NO_OID));
        return out;
      }
    }
    // The server answers in SPNEGO; the Kerberos mechanism takes the token
    // inside.
    std::string_view mech_input;
    if (!first) {
      std::string error;
      std::optional<AuthToken> parsed = parseAuthToken(token, error);
      if (!parsed) {
        out.error = "the server's token: " + error;
        return out;
      }
      if (parsed->mechanism != AuthMechanism::Kerberos || !parsed->mech_token) {
        out.error = "the server's token carries no Kerberos answer";
        return out;
      }
      mech_input = *parsed->mech_token;
    }
    gss_buffer_desc input = bufferOf(mech_input);
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    Bindings bindings(binding);
    OM_uint32 minor = 0;
    const OM_uint32 major = gss_init_sec_context(
        &minor, init_cred_, &init_context_, target_, gss_mech_krb5, GSS_C_MUTUAL_FLAG, 0,
        bindings.get(), first ? GSS_C_NO_BUFFER : &input, nullptr, &output, nullptr, nullptr);
    const std::string mech_output = take(output);
    if (GSS_ERROR(major)) {
      out.error = gssMessage(major, minor, gss_mech_krb5);
      if (!tgt_error_.empty()) {
        out.error += " (" + tgt_error_ + ")";
      }
      return out;
    }
    out.complete = (major & GSS_S_CONTINUE_NEEDED) == 0;
    if (!mech_output.empty()) {
      out.token = first ? spnegoKerberosInit(mech_output) : spnegoResponse(mech_output);
    }
    return out;
  }

private:
  std::shared_ptr<const GssTerminator> terminator_; // Keeps creds_ alive.
  const GssTerminator::Creds& creds_;
  const bool delegate_;
  gss_ctx_id_t accept_context_ = GSS_C_NO_CONTEXT;
  gss_ctx_id_t init_context_ = GSS_C_NO_CONTEXT;
  gss_cred_id_t delegated_ = GSS_C_NO_CREDENTIAL;
  gss_cred_id_t init_cred_ = GSS_C_NO_CREDENTIAL; // Not owned.
  gss_name_t target_ = GSS_C_NO_NAME;
  std::string principal_;
  std::string tgt_error_; // Why the proxy's TGT couldn't be had, if so.
};

} // namespace

GssTerminator::~GssTerminator() = default;

bool GssTerminator::ensureProxyTgt(std::string& error) const {
  std::lock_guard<std::mutex> lock(tgt_mutex_);
  krb5_context ctx = threadKrb5Context(error);
  if (ctx == nullptr) {
    return false;
  }
  krb5_keytab keytab = nullptr;
  krb5_ccache ccache = nullptr;
  krb5_principal client = nullptr;
  krb5_principal tgs = nullptr;
  krb5_creds cached{};
  krb5_creds fresh{};
  bool have_cached = false;
  bool have_fresh = false;
  auto fail = [&](std::string_view what, krb5_error_code code) {
    error = std::format("{}: {}", what, krb5Message(ctx, code));
    return false;
  };
  auto done = [&](bool ok) {
    if (have_cached) {
      krb5_free_cred_contents(ctx, &cached);
    }
    if (have_fresh) {
      krb5_free_cred_contents(ctx, &fresh);
    }
    krb5_free_principal(ctx, tgs);
    krb5_free_principal(ctx, client);
    if (ccache != nullptr) {
      krb5_cc_close(ctx, ccache);
    }
    if (keytab != nullptr) {
      krb5_kt_close(ctx, keytab);
    }
    return ok;
  };

  if (krb5_error_code code = krb5_kt_resolve(ctx, tgt_keytab_.c_str(), &keytab)) {
    return done(fail("keytab", code));
  }
  if (!tgt_principal_.empty()) {
    // The one that was asked for (its realm, if not given, is the default).
    if (krb5_error_code code = krb5_parse_name(ctx, tgt_principal_.c_str(), &client)) {
      return done(fail("principal " + tgt_principal_, code));
    }
  } else {
    // The keytab's first principal, as MIT's own client keytab use picks it.
    krb5_kt_cursor cursor;
    if (krb5_error_code code = krb5_kt_start_seq_get(ctx, keytab, &cursor)) {
      return done(fail("keytab", code));
    }
    krb5_keytab_entry entry;
    krb5_error_code code = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
    if (code == 0) {
      code = krb5_copy_principal(ctx, entry.principal, &client);
      krb5_free_keytab_entry_contents(ctx, &entry);
    }
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    if (code != 0) {
      return done(fail("keytab", code));
    }
  }
  if (!acceptor_keytab_.empty()) {
    const std::string stamp = fileStamp(tgt_keytab_) + "|" + fileStamp(service_keytab_);
    if (stamp != acceptor_stamp_) {
      if (!fillAcceptorKeytab(ctx, acceptor_keytab_, tgt_keytab_, client, service_keytab_, error)) {
        return done(false);
      }
      acceptor_stamp_ = stamp;
    }
  }
  if (krb5_error_code c = krb5_cc_resolve(ctx, ccache_.c_str(), &ccache)) {
    return done(fail("ccache", c));
  }
  const krb5_data& realm = client->realm;
  if (krb5_error_code c = krb5_build_principal_ext(ctx, &tgs, realm.length, realm.data,
                                                   KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                                   realm.length, realm.data, 0)) {
    return done(fail("TGT name", c));
  }
  // A TGT good for a while yet is kept.
  krb5_creds match{};
  match.client = client;
  match.server = tgs;
  if (krb5_cc_retrieve_cred(ctx, ccache, 0, &match, &cached) == 0) {
    have_cached = true;
    if (static_cast<int64_t>(cached.times.endtime) - std::time(nullptr) > kRenewBefore) {
      return done(true);
    }
  }
  if (krb5_error_code c =
          krb5_get_init_creds_keytab(ctx, &fresh, client, keytab, 0, nullptr, nullptr)) {
    return done(fail("getting a TGT", c));
  }
  have_fresh = true;
  if (krb5_error_code c = krb5_cc_initialize(ctx, ccache, client)) {
    return done(fail("ccache", c));
  }
  if (krb5_error_code c = krb5_cc_store_cred(ctx, ccache, &fresh)) {
    return done(fail("ccache", c));
  }
  return done(true);
}

std::shared_ptr<const GssTerminator> GssTerminator::create(const TerminateOptions& options,
                                                           std::string& error) {
  if (!checkKeytab(options.keytab_path, error)) {
    return nullptr;
  }
  if (!options.delegate && options.client_keytab_path.empty()) {
    error = "service_account needs the client keytab of the account to log in as";
    return nullptr;
  }
  if (!options.client_keytab_path.empty() && !checkKeytab(options.client_keytab_path, error)) {
    return nullptr;
  }
  std::shared_ptr<GssTerminator> terminator(new GssTerminator());
  terminator->delegate_ = options.delegate;
  terminator->creds_ = std::make_unique<Creds>();
  const std::string keytab = "FILE:" + options.keytab_path;
  const std::string client = "FILE:" + options.client_keytab_path;
  const std::string ccache = memoryCcache();
  terminator->ccache_ = ccache;

  if (options.delegate) {
    // The acceptor credential initiates too, which lets MIT keep a client's
    // ticket as evidence for S4U2Proxy. It initiates as the proxy's own
    // principal: by default the first of the service keytab, else the one
    // named (from its own keytab if given) - which is had as its TGT now, so
    // that the credential takes that identity from the ccache. The credential
    // itself is unnamed: a named one would look for that principal's keys to
    // accept with.
    const bool explicit_principal = !options.principal.empty() || !options.client_keytab_path.empty();
    terminator->tgt_keytab_ = options.client_keytab_path.empty() ? keytab : client;
    terminator->tgt_principal_ = options.principal;
    if (explicit_principal) {
      terminator->service_keytab_ = keytab;
      terminator->acceptor_keytab_ = memoryKeytab();
      krb5_context kctx = threadKrb5Context(error);
      if (kctx == nullptr) {
        return nullptr;
      }
      if (krb5_error_code code = krb5_kt_resolve(kctx, terminator->acceptor_keytab_.c_str(),
                                                 &terminator->creds_->memory_keytab)) {
        error = "acceptor keytab: " + krb5Message(kctx, code);
        return nullptr;
      }
      std::string tgt_error;
      if (!terminator->ensureProxyTgt(tgt_error)) {
        error = "the proxy's own TGT: " + tgt_error;
        return nullptr;
      }
    }
    terminator->creds_->acceptor = acquire(
        GSS_C_NO_NAME, GSS_C_BOTH,
        {{"keytab", explicit_principal ? terminator->acceptor_keytab_ : keytab},
         {"client_keytab", terminator->tgt_keytab_},
         {"ccache", ccache}},
        error);
    if (terminator->creds_->acceptor == GSS_C_NO_CREDENTIAL) {
      error = "acceptor credentials: " + error;
      return nullptr;
    }
    return terminator;
  }

  terminator->creds_->acceptor = acquire(GSS_C_NO_NAME, GSS_C_ACCEPT, {{"keytab", keytab}}, error);
  if (terminator->creds_->acceptor == GSS_C_NO_CREDENTIAL) {
    error = "acceptor credentials: " + error;
    return nullptr;
  }
  gss_name_t name = GSS_C_NO_NAME;
  if (!options.principal.empty()) {
    gss_buffer_desc text = bufferOf(options.principal);
    OM_uint32 minor = 0;
    const OM_uint32 major = gss_import_name(&minor, &text, GSS_KRB5_NT_PRINCIPAL_NAME, &name);
    if (GSS_ERROR(major)) {
      error = std::format("principal {}: {}", options.principal,
                          gssMessage(major, minor, GSS_C_NO_OID));
      return nullptr;
    }
  }
  terminator->creds_->initiator =
      acquire(name, GSS_C_INITIATE, {{"client_keytab", client}, {"ccache", ccache}}, error);
  OM_uint32 minor;
  gss_release_name(&minor, &name);
  if (terminator->creds_->initiator == GSS_C_NO_CREDENTIAL) {
    error = "service account credentials: " + error;
    return nullptr;
  }
  return terminator;
}

std::shared_ptr<KerberosExchange> GssTerminator::start() const {
  return std::make_shared<GssExchange>(shared_from_this(), *creds_, delegate_);
}

} // namespace MssqlProxy

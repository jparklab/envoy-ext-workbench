#include "kerberos.h"

#include <cstdlib>
#include <format>
#include <memory>

#include "krb5_api.h"
#include "krb5_messages.h"

namespace MssqlProxy {

namespace {

// One krb5_context per thread: contexts are not shared between threads.
krb5_context threadContext(const Krb5Api& api, std::string& error) {
  struct Holder {
    const Krb5Api* api = nullptr;
    krb5_context context = nullptr;
    ~Holder() {
      if (context != nullptr) {
        api->krb5_free_context(context);
      }
    }
  };
  thread_local Holder holder;
  if (holder.context == nullptr) {
    if (krb5_error_code code = api.krb5_init_context(&holder.context)) {
      error = std::format("cannot create a Kerberos context (error {})", code);
      holder.context = nullptr;
      return nullptr;
    }
    holder.api = &api;
  }
  return holder.context;
}

std::string_view view(const krb5_data& d) { return {d.data, d.length}; }

} // namespace

std::shared_ptr<const KeytabTicketReader> KeytabTicketReader::create(const std::string& path,
                                                                     std::string& error) {
  const Krb5Api* api = loadKrb5(error);
  if (api == nullptr) {
    return nullptr;
  }
  krb5_context ctx = threadContext(*api, error);
  if (ctx == nullptr) {
    return nullptr;
  }
  const std::string name = "FILE:" + path;
  krb5_keytab kt = nullptr;
  if (krb5_error_code code = api->krb5_kt_resolve(ctx, name.c_str(), &kt)) {
    error = std::format("keytab {}: {}", path, api->message(ctx, code));
    return nullptr;
  }
  krb5_kt_cursor cursor;
  size_t keys = 0;
  krb5_error_code code = api->krb5_kt_start_seq_get(ctx, kt, &cursor);
  if (code == 0) {
    krb5_keytab_entry entry;
    while (api->krb5_kt_next_entry(ctx, kt, &entry, &cursor) == 0) {
      ++keys;
      api->krb5_free_keytab_entry_contents(ctx, &entry);
    }
    api->krb5_kt_end_seq_get(ctx, kt, &cursor);
  }
  api->krb5_kt_close(ctx, kt);
  if (code != 0) {
    error = std::format("keytab {}: {}", path, api->message(ctx, code));
    return nullptr;
  }
  if (keys == 0) {
    error = std::format("keytab {} has no keys", path);
    return nullptr;
  }
  return std::shared_ptr<const KeytabTicketReader>(new KeytabTicketReader(name));
}

std::optional<KerberosTicketInfo> KeytabTicketReader::read(std::string_view ap_req_der,
                                                           int64_t now,
                                                           std::string& error) const {
  std::optional<KrbApReq> ap_req = parseApReq(ap_req_der, error);
  if (!ap_req) {
    error = "AP-REQ: " + error;
    return std::nullopt;
  }
  const Krb5Api* api = loadKrb5(error);
  krb5_context ctx = api != nullptr ? threadContext(*api, error) : nullptr;
  if (ctx == nullptr) {
    return std::nullopt;
  }
  const std::string service = principalString(ap_req->ticket_sname, ap_req->ticket_realm);

  krb5_data ticket_der{};
  ticket_der.magic = KV5M_DATA;
  ticket_der.length = static_cast<unsigned int>(ap_req->ticket.size());
  ticket_der.data = const_cast<char*>(ap_req->ticket.data());
  krb5_ticket* raw_ticket = nullptr;
  if (krb5_error_code code = api->krb5_decode_ticket(&ticket_der, &raw_ticket)) {
    error = "ticket: " + api->message(ctx, code);
    return std::nullopt;
  }
  auto free_ticket = [api, ctx](krb5_ticket* t) { api->krb5_free_ticket(ctx, t); };
  std::unique_ptr<krb5_ticket, decltype(free_ticket)> ticket(raw_ticket, free_ticket);

  krb5_keytab kt = nullptr;
  if (krb5_error_code code = api->krb5_kt_resolve(ctx, keytab_name_.c_str(), &kt)) {
    error = "keytab: " + api->message(ctx, code);
    return std::nullopt;
  }
  krb5_error_code code = api->krb5_server_decrypt_ticket_keytab(ctx, kt, ticket.get());
  api->krb5_kt_close(ctx, kt);
  if (code != 0) {
    error = std::format("ticket for {}: {}", service, api->message(ctx, code));
    return std::nullopt;
  }
  const krb5_enc_tkt_part& part = *ticket->enc_part2;
  if (part.flags & TKT_FLG_INVALID) {
    error = std::format("ticket for {} is marked invalid", service);
    return std::nullopt;
  }
  const int64_t start = part.times.starttime != 0 ? part.times.starttime : part.times.authtime;
  if (now + kKerberosClockSkew < start) {
    error = std::format("ticket for {} is not yet valid", service);
    return std::nullopt;
  }
  if (now - kKerberosClockSkew > static_cast<int64_t>(part.times.endtime)) {
    error = std::format("ticket for {} has expired", service);
    return std::nullopt;
  }

  // The authenticator, with the session key the ticket carries.
  krb5_enc_data encrypted{};
  encrypted.magic = KV5M_ENC_DATA;
  encrypted.enctype = ap_req->authenticator.etype;
  encrypted.kvno = ap_req->authenticator.kvno.value_or(0);
  encrypted.ciphertext.magic = KV5M_DATA;
  encrypted.ciphertext.length = static_cast<unsigned int>(ap_req->authenticator.cipher.size());
  encrypted.ciphertext.data = const_cast<char*>(ap_req->authenticator.cipher.data());
  std::string plain_bytes(ap_req->authenticator.cipher.size(), '\0');
  krb5_data plain{};
  plain.magic = KV5M_DATA;
  plain.length = static_cast<unsigned int>(plain_bytes.size());
  plain.data = plain_bytes.data();
  if (krb5_error_code c = api->krb5_c_decrypt(ctx, part.session, KRB5_KEYUSAGE_AP_REQ_AUTH,
                                              nullptr, &encrypted, &plain)) {
    error = "authenticator: " + api->message(ctx, c);
    return std::nullopt;
  }
  std::optional<KrbAuthenticator> authenticator =
      parseAuthenticator(std::string_view(plain.data, plain.length), error);
  if (!authenticator) {
    error = "authenticator: " + error;
    return std::nullopt;
  }
  const krb5_principal_data& client = *part.client;
  bool same = authenticator->crealm == view(client.realm) &&
              authenticator->cname.components.size() == static_cast<size_t>(client.length);
  for (size_t i = 0; same && i < authenticator->cname.components.size(); ++i) {
    same = authenticator->cname.components[i] == view(client.data[i]);
  }
  if (!same) {
    error = "the authenticator names a different client than the ticket";
    return std::nullopt;
  }
  if (std::llabs(now - authenticator->ctime) > kKerberosClockSkew) {
    error = "the authenticator's time is outside the clock skew";
    return std::nullopt;
  }

  char* name = nullptr;
  if (krb5_error_code c = api->krb5_unparse_name(ctx, part.client, &name)) {
    error = "client name: " + api->message(ctx, c);
    return std::nullopt;
  }
  KerberosTicketInfo info{name, service, static_cast<int64_t>(part.times.endtime)};
  api->krb5_free_unparsed_name(ctx, name);
  return info;
}

} // namespace MssqlProxy

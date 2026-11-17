#include "krb5_messages.h"

#include <format>

#include "der.h"

namespace MssqlProxy {

namespace {

constexpr int64_t kKrbVersion = 5;
constexpr int64_t kKrbApReqType = 14;

std::optional<int32_t> int32(std::optional<int64_t> v, const char* what, std::string& error) {
  if (!v) {
    return std::nullopt;
  }
  if (*v < INT32_MIN || *v > INT32_MAX) {
    error = std::format("{} out of range", what);
    return std::nullopt;
  }
  return static_cast<int32_t>(*v);
}

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
std::optional<KrbPrincipalName> readPrincipal(Der& outer, unsigned n, std::string& error) {
  auto seq = outer.readExplicit(n, kDerSequence, error);
  if (!seq) {
    return std::nullopt;
  }
  Der fields(*seq);
  KrbPrincipalName name;
  auto type = int32(fields.readExplicitInteger(0, error), "name-type", error);
  if (!type) {
    return std::nullopt;
  }
  name.type = *type;
  auto strings = fields.readExplicit(1, kDerSequence, error);
  if (!strings) {
    return std::nullopt;
  }
  Der list(*strings);
  while (!list.empty()) {
    auto s = list.read(kDerGeneralString, error);
    if (!s) {
      return std::nullopt;
    }
    name.components.emplace_back(*s);
  }
  if (name.components.empty()) {
    error = "empty principal name";
    return std::nullopt;
  }
  return name;
}

// EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }
std::optional<KrbEncryptedData> readEncryptedData(Der& outer, unsigned n, std::string& error) {
  auto seq = outer.readExplicit(n, kDerSequence, error);
  if (!seq) {
    return std::nullopt;
  }
  Der fields(*seq);
  KrbEncryptedData out;
  auto etype = int32(fields.readExplicitInteger(0, error), "etype", error);
  if (!etype) {
    return std::nullopt;
  }
  out.etype = *etype;
  if (fields.nextIs(1)) {
    auto kvno = fields.readExplicitInteger(1, error);
    if (!kvno) {
      return std::nullopt;
    }
    out.kvno = static_cast<uint32_t>(*kvno);
  }
  auto cipher = fields.readExplicit(2, kDerOctetString, error);
  if (!cipher) {
    return std::nullopt;
  }
  out.cipher = *cipher;
  return out;
}

} // namespace

std::string principalString(const KrbPrincipalName& name, std::string_view realm) {
  std::string out;
  for (const std::string& c : name.components) {
    if (!out.empty()) {
      out += '/';
    }
    out += c;
  }
  return out + "@" + std::string(realm);
}

std::optional<KrbApReq> parseApReq(std::string_view der, std::string& error) {
  Der top(der);
  auto app = top.read(derApplication(14), error);
  if (!app) {
    return std::nullopt;
  }
  Der seq_der(*app);
  auto seq = seq_der.read(kDerSequence, error);
  if (!seq) {
    return std::nullopt;
  }
  Der fields(*seq);
  auto pvno = fields.readExplicitInteger(0, error);
  auto type = pvno ? fields.readExplicitInteger(1, error) : std::nullopt;
  if (!type) {
    return std::nullopt;
  }
  if (*pvno != kKrbVersion || *type != kKrbApReqType) {
    error = "not a Kerberos 5 AP-REQ";
    return std::nullopt;
  }
  KrbApReq out;
  auto options = fields.readExplicit(2, kDerBitString, error);
  if (!options) {
    return std::nullopt;
  }
  for (size_t i = 1; i < options->size() && i <= 4; ++i) { // Byte 0: unused-bit count.
    out.ap_options |= static_cast<uint32_t>(static_cast<uint8_t>((*options)[i])) << (8 * (4 - i));
  }

  auto ticket_wrapper = fields.read(derContext(3), error);
  if (!ticket_wrapper) {
    return std::nullopt;
  }
  Der ticket_der(*ticket_wrapper);
  auto ticket = ticket_der.readRaw(derApplication(1), error);
  if (!ticket) {
    return std::nullopt;
  }
  out.ticket = *ticket;
  {
    Der t(*ticket);
    auto body = t.read(derApplication(1), error);
    Der body_der(body ? *body : std::string_view());
    auto tseq = body ? body_der.read(kDerSequence, error) : std::nullopt;
    if (!tseq) {
      return std::nullopt;
    }
    Der tfields(*tseq);
    auto vno = tfields.readExplicitInteger(0, error);
    auto realm = vno ? tfields.readExplicitString(1, error) : std::nullopt;
    if (!realm) {
      return std::nullopt;
    }
    auto sname = readPrincipal(tfields, 2, error);
    if (!sname) {
      return std::nullopt;
    }
    out.ticket_realm = *realm;
    out.ticket_sname = *sname;
  }
  auto authenticator = readEncryptedData(fields, 4, error);
  if (!authenticator) {
    return std::nullopt;
  }
  out.authenticator = *authenticator;
  return out;
}

std::optional<KrbAuthenticator> parseAuthenticator(std::string_view der, std::string& error) {
  Der top(der);
  auto app = top.read(derApplication(2), error);
  if (!app) {
    return std::nullopt;
  }
  Der seq_der(*app);
  auto seq = seq_der.read(kDerSequence, error);
  if (!seq) {
    return std::nullopt;
  }
  Der fields(*seq);
  KrbAuthenticator out;
  auto vno = fields.readExplicitInteger(0, error);
  if (!vno) {
    return std::nullopt;
  }
  if (*vno != kKrbVersion) {
    error = "not a Kerberos 5 authenticator";
    return std::nullopt;
  }
  auto crealm = fields.readExplicitString(1, error);
  if (!crealm) {
    return std::nullopt;
  }
  out.crealm = *crealm;
  auto cname = readPrincipal(fields, 2, error);
  if (!cname) {
    return std::nullopt;
  }
  out.cname = *cname;
  if (fields.nextIs(3) && !fields.skip(error)) { // cksum
    return std::nullopt;
  }
  auto cusec = fields.readExplicitInteger(4, error);
  auto ctime = cusec ? fields.readExplicitTime(5, error) : std::nullopt;
  if (!ctime) {
    return std::nullopt;
  }
  out.cusec = static_cast<uint32_t>(*cusec);
  out.ctime = *ctime;
  return out; // subkey, seq-number, authorization-data: not needed.
}

} // namespace MssqlProxy

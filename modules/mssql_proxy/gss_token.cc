#include "gss_token.h"

#include <format>

namespace MssqlProxy {

namespace {

// DER-encoded OID contents (without tag and length).
constexpr std::string_view kSpnegoOid{"\x2b\x06\x01\x05\x05\x02", 6};          // 1.3.6.1.5.5.2
constexpr std::string_view kKrb5Oid{"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9};   // 1.2.840.113554.1.2.2
constexpr std::string_view kMsKrb5Oid{"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", 9}; // 1.2.840.48018.1.2.2
constexpr std::string_view kNtlmOid{"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a", 10}; // 1.3.6.1.4.1.311.2.2.10
constexpr std::string_view kNtlmSignature{"NTLMSSP\0", 8};

constexpr uint8_t kTagApplication0 = 0x60; // GSS InitialContextToken
constexpr uint8_t kTagSequence = 0x30;
constexpr uint8_t kTagOctetString = 0x04;
constexpr uint8_t kTagOid = 0x06;
constexpr uint8_t kTagContext0 = 0xa0;
constexpr uint8_t kTagContext1 = 0xa1;
constexpr uint8_t kTagContext2 = 0xa2;

AuthMechanism mechanismOf(std::string_view oid) {
  if (oid == kKrb5Oid || oid == kMsKrb5Oid) {
    return AuthMechanism::Kerberos;
  }
  if (oid == kNtlmOid) {
    return AuthMechanism::Ntlm;
  }
  return AuthMechanism::Unknown;
}

// A reader over DER TLVs. Only single-byte tags occur in these structures.
class Der {
public:
  explicit Der(std::string_view data) : data_(data) {}

  bool empty() const { return pos_ == data_.size(); }
  std::optional<uint8_t> peekTag() const {
    return empty() ? std::nullopt : std::optional<uint8_t>(static_cast<uint8_t>(data_[pos_]));
  }
  std::string_view rest() const { return data_.substr(pos_); }

  // The contents of the next TLV, which must have this tag.
  std::optional<std::string_view> read(uint8_t tag, std::string& error) {
    if (empty() || static_cast<uint8_t>(data_[pos_]) != tag) {
      error = std::format("expected DER tag 0x{:02x}", tag);
      return std::nullopt;
    }
    size_t pos = pos_ + 1;
    if (pos >= data_.size()) {
      error = "DER length missing";
      return std::nullopt;
    }
    size_t len = static_cast<uint8_t>(data_[pos++]);
    if (len & 0x80) {
      const size_t n = len & 0x7f;
      if (n == 0 || n > 4) {
        error = "unsupported DER length"; // Indefinite (BER) or absurdly long.
        return std::nullopt;
      }
      if (data_.size() - pos < n) {
        error = "DER length truncated";
        return std::nullopt;
      }
      len = 0;
      for (size_t i = 0; i < n; ++i) {
        len = (len << 8) | static_cast<uint8_t>(data_[pos++]);
      }
    }
    if (len > data_.size() - pos) {
      error = "DER value truncated";
      return std::nullopt;
    }
    pos_ = pos + len;
    return data_.substr(pos, len);
  }

  // Skips the next TLV, whatever its tag.
  bool skip(std::string& error) {
    auto tag = peekTag();
    return tag && read(*tag, error).has_value();
  }

private:
  std::string_view data_;
  size_t pos_ = 0;
};

// The mechanism's message inside a mechToken / responseToken.
bool classifyInner(std::string_view inner, AuthToken& out, std::string& error);

// GSS InitialContextToken: [APPLICATION 0] { thisMech OID, innerToken }.
// Returns the OID and leaves the inner token in inner.
bool readGssFraming(std::string_view token, std::string_view& oid, std::string_view& inner,
                    std::string& error) {
  Der der(token);
  auto body = der.read(kTagApplication0, error);
  if (!body) {
    return false;
  }
  if (!der.empty()) {
    error = "data after the GSS token";
    return false;
  }
  Der fields(*body);
  auto mech = fields.read(kTagOid, error);
  if (!mech) {
    return false;
  }
  oid = *mech;
  inner = fields.rest();
  return true;
}

bool classifyKrb5(std::string_view inner, AuthToken& out, std::string& error) {
  if (inner.size() < 2) {
    error = "Kerberos GSS token without TOK_ID";
    return false;
  }
  out.mechanism = AuthMechanism::Kerberos;
  out.krb5_tok_id = static_cast<uint16_t>((static_cast<uint8_t>(inner[0]) << 8) |
                                          static_cast<uint8_t>(inner[1]));
  out.inner = inner.substr(2);
  return true;
}

bool classifyInner(std::string_view inner, AuthToken& out, std::string& error) {
  if (inner.starts_with(kNtlmSignature)) {
    out.mechanism = AuthMechanism::Ntlm;
    out.inner = inner;
    return true;
  }
  if (!inner.empty() && static_cast<uint8_t>(inner[0]) == kTagApplication0) {
    std::string_view oid, rest;
    if (!readGssFraming(inner, oid, rest, error)) {
      return false;
    }
    if (mechanismOf(oid) == AuthMechanism::Kerberos) {
      return classifyKrb5(rest, out, error);
    }
  }
  out.mechanism = AuthMechanism::Unknown;
  out.inner = inner;
  return true;
}

// NegTokenInit ::= SEQUENCE { mechTypes [0], reqFlags [1], mechToken [2],
// mechListMIC [3] } (NegTokenInit2 has negHints at [3]; both skipped).
bool parseNegTokenInit(std::string_view body, AuthToken& out, std::string& error) {
  Der outer(body);
  auto seq = outer.read(kTagSequence, error);
  if (!seq) {
    return false;
  }
  Der fields(*seq);
  std::optional<std::string_view> mech_token;
  while (!fields.empty()) {
    const uint8_t tag = *fields.peekTag();
    if (tag == kTagContext0) {
      auto types = fields.read(kTagContext0, error);
      if (!types) {
        return false;
      }
      Der list_der(*types);
      auto list = list_der.read(kTagSequence, error);
      if (!list) {
        return false;
      }
      Der oids(*list);
      while (!oids.empty()) {
        auto oid = oids.read(kTagOid, error);
        if (!oid) {
          return false;
        }
        out.offered.push_back(mechanismOf(*oid));
      }
    } else if (tag == kTagContext2) {
      auto wrapped = fields.read(kTagContext2, error);
      if (!wrapped) {
        return false;
      }
      Der octets(*wrapped);
      mech_token = octets.read(kTagOctetString, error);
      if (!mech_token) {
        return false;
      }
    } else if (!fields.skip(error)) {
      return false;
    }
  }
  if (out.offered.empty()) {
    error = "SPNEGO NegTokenInit offers no mechanism";
    return false;
  }
  if (!mech_token) {
    out.mechanism = out.offered.front();
    return true;
  }
  return classifyInner(*mech_token, out, error);
}

// NegTokenResp ::= SEQUENCE { negState [0], supportedMech [1],
// responseToken [2], mechListMIC [3] }.
bool parseNegTokenResp(std::string_view body, AuthToken& out, std::string& error) {
  Der outer(body);
  auto seq = outer.read(kTagSequence, error);
  if (!seq) {
    return false;
  }
  Der fields(*seq);
  AuthMechanism supported = AuthMechanism::Unknown;
  std::optional<std::string_view> response;
  while (!fields.empty()) {
    const uint8_t tag = *fields.peekTag();
    if (tag == kTagContext1) {
      auto wrapped = fields.read(kTagContext1, error);
      if (!wrapped) {
        return false;
      }
      Der oid_der(*wrapped);
      auto oid = oid_der.read(kTagOid, error);
      if (!oid) {
        return false;
      }
      supported = mechanismOf(*oid);
    } else if (tag == kTagContext2) {
      auto wrapped = fields.read(kTagContext2, error);
      if (!wrapped) {
        return false;
      }
      Der octets(*wrapped);
      response = octets.read(kTagOctetString, error);
      if (!response) {
        return false;
      }
    } else if (!fields.skip(error)) {
      return false;
    }
  }
  if (!response) {
    out.mechanism = supported;
    return true;
  }
  if (!classifyInner(*response, out, error)) {
    return false;
  }
  if (out.mechanism == AuthMechanism::Unknown) {
    // A bare Kerberos message (e.g. AP-REP without GSS framing) or other.
    out.mechanism = supported;
  }
  return true;
}

} // namespace

const char* authMechanismName(AuthMechanism mechanism) {
  switch (mechanism) {
  case AuthMechanism::Kerberos:
    return "kerberos";
  case AuthMechanism::Ntlm:
    return "ntlm";
  case AuthMechanism::Unknown:
    break;
  }
  return "unknown";
}

std::optional<AuthToken> parseAuthToken(std::string_view token, std::string& error) {
  AuthToken out;
  if (token.empty()) {
    error = "empty authentication token";
    return std::nullopt;
  }
  if (token.starts_with(kNtlmSignature)) {
    out.mechanism = AuthMechanism::Ntlm;
    out.inner = token;
    return out;
  }
  const uint8_t first = static_cast<uint8_t>(token[0]);
  if (first == kTagApplication0) {
    std::string_view oid, inner;
    if (!readGssFraming(token, oid, inner, error)) {
      return std::nullopt;
    }
    if (oid == kSpnegoOid) {
      out.spnego = true;
      Der der(inner);
      auto body = der.read(kTagContext0, error); // negTokenInit
      if (!body || !der.empty()) {
        if (error.empty()) {
          error = "data after SPNEGO NegTokenInit";
        }
        return std::nullopt;
      }
      if (!parseNegTokenInit(*body, out, error)) {
        return std::nullopt;
      }
      return out;
    }
    if (mechanismOf(oid) == AuthMechanism::Kerberos) {
      if (!classifyKrb5(inner, out, error)) {
        return std::nullopt;
      }
      return out;
    }
    error = "GSS token of an unknown mechanism";
    return std::nullopt;
  }
  if (first == kTagContext1) { // SPNEGO negTokenResp, sent without GSS framing.
    out.spnego = true;
    Der der(token);
    auto body = der.read(kTagContext1, error);
    if (!body || !der.empty()) {
      if (error.empty()) {
        error = "data after SPNEGO NegTokenResp";
      }
      return std::nullopt;
    }
    if (!parseNegTokenResp(*body, out, error)) {
      return std::nullopt;
    }
    return out;
  }
  error = std::format("unrecognised authentication token (first byte 0x{:02x})", first);
  return std::nullopt;
}

} // namespace MssqlProxy

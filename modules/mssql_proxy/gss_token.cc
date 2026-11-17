#include "gss_token.h"

#include <format>

#include "der.h"

namespace MssqlProxy {

namespace {

// DER-encoded OID contents (without tag and length).
constexpr std::string_view kSpnegoOid{"\x2b\x06\x01\x05\x05\x02", 6};          // 1.3.6.1.5.5.2
constexpr std::string_view kKrb5Oid{"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9};   // 1.2.840.113554.1.2.2
constexpr std::string_view kMsKrb5Oid{"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", 9}; // 1.2.840.48018.1.2.2
constexpr std::string_view kNtlmOid{"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a", 10}; // 1.3.6.1.4.1.311.2.2.10
constexpr std::string_view kNtlmSignature{"NTLMSSP\0", 8};

constexpr uint8_t kTagApplication0 = 0x60; // GSS InitialContextToken
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
  auto mech = fields.read(kDerOid, error);
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
  auto seq = outer.read(kDerSequence, error);
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
      auto list = list_der.read(kDerSequence, error);
      if (!list) {
        return false;
      }
      Der oids(*list);
      while (!oids.empty()) {
        auto oid = oids.read(kDerOid, error);
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
      mech_token = octets.read(kDerOctetString, error);
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
  out.mech_token = mech_token;
  return classifyInner(*mech_token, out, error);
}

// NegTokenResp ::= SEQUENCE { negState [0], supportedMech [1],
// responseToken [2], mechListMIC [3] }.
bool parseNegTokenResp(std::string_view body, AuthToken& out, std::string& error) {
  Der outer(body);
  auto seq = outer.read(kDerSequence, error);
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
      auto oid = oid_der.read(kDerOid, error);
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
      response = octets.read(kDerOctetString, error);
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
  out.mech_token = response;
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
    out.mech_token = token;
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
      out.mech_token = token;
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

std::string spnegoKerberosInit(std::string_view krb5_token) {
  // NegTokenInit ::= SEQUENCE { mechTypes [0] SEQUENCE OF OID, mechToken [2] OCTET STRING }
  const std::string mech_types =
      derEncode(kTagContext0, derEncode(kDerSequence, derEncode(kDerOid, kKrb5Oid)));
  const std::string mech_token = derEncode(kTagContext2, derEncode(kDerOctetString, krb5_token));
  const std::string init = derEncode(kTagContext0, derEncode(kDerSequence, mech_types + mech_token));
  return derEncode(kTagApplication0, derEncode(kDerOid, kSpnegoOid) + init);
}

std::string spnegoResponse(std::string_view mech_token) {
  // NegTokenResp ::= SEQUENCE { responseToken [2] OCTET STRING }
  return derEncode(kTagContext1,
                   derEncode(kDerSequence,
                             derEncode(kTagContext2, derEncode(kDerOctetString, mech_token))));
}

} // namespace MssqlProxy

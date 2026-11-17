#pragma once

// Classifies the authentication tokens an integrated login carries (LOGIN7
// SSPI data, SSPI packets, the server's SSPI tokens) without verifying them:
// which mechanism, and the mechanism's own message inside any wrapping.
// Handles SPNEGO (RFC 4178) NegTokenInit and NegTokenResp, a bare GSS-API
// Kerberos token (RFC 4121 framing), and raw NTLMSSP. All ASN.1 DER is
// bounds-checked. No Envoy dependency.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace MssqlProxy {

enum class AuthMechanism { Unknown, Kerberos, Ntlm };

const char* authMechanismName(AuthMechanism mechanism);

struct AuthToken {
  // The mechanism of the inner token, or with no inner token the first one
  // SPNEGO offered.
  AuthMechanism mechanism = AuthMechanism::Unknown;
  bool spnego = false;
  // SPNEGO NegTokenInit: the mechanisms offered, in order.
  std::vector<AuthMechanism> offered;
  // The mechanism's message, viewing the parsed token: the Kerberos message
  // after the GSS header and TOK_ID (e.g. the AP-REQ), or the NTLMSSP message.
  // Empty when the token carries none.
  std::string_view inner;
  // Kerberos only: the GSS TOK_ID (0x0100 AP-REQ, 0x0200 AP-REP, 0x0300 error).
  std::optional<uint16_t> krb5_tok_id;
};

// nullopt and error set when the token is not one of the forms above, or is
// malformed.
std::optional<AuthToken> parseAuthToken(std::string_view token, std::string& error);

} // namespace MssqlProxy

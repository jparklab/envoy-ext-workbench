#pragma once

// Follows one connection's login: how the client authenticates, who it
// claims to be, the allow/deny policy, and the server's verdict. Fed by the
// TLS bridge with the plain-text login messages. No Envoy dependency.
//
// Identities are claims until the server accepts the login (LOGINACK); the
// policy only ever denies on them, which a false claim can't exploit.

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "gss_token.h"
#include "login7.h"
#include "tds.h"

namespace MssqlProxy {

struct AuthSettings {
  // NTLM logins pass through (the server verifies them), or are refused.
  bool ntlm_allowed = true;
  // NTLMv1 responses (24 bytes) pass through, or are refused.
  bool ntlm_v1_allowed = true;
  // Identities refused before the server is asked, compared ignoring ASCII
  // case: SQL login names; for NTLM "DOMAIN\user" with the domain as the client
  // sent it (NetBIOS or DNS name), or the bare user name it sent (e.g. a UPN).
  std::vector<std::string> deny;
};

enum class LoginMethod {
  Sql,        // User name and password in LOGIN7.
  Kerberos,   // Integrated, Kerberos.
  Ntlm,       // Integrated, NTLM.
  Integrated, // Integrated, mechanism not recognised.
  Federated,  // Entra ID / federated authentication (LOGIN7 feature extension).
};

const char* loginMethodName(LoginMethod method);

enum class LoginResult { Pending, Succeeded, Failed, Denied };

const char* loginResultName(LoginResult result);

// Refusal of a login by the proxy.
struct Denial {
  std::string reason;      // For logs.
  std::string client_text; // For the client's ERROR 18456 message.
};

class LoginAuth {
public:
  explicit LoginAuth(std::shared_ptr<const AuthSettings> settings);

  // The client's LOGIN7 and its later SSPI messages (0x11). nullopt: forward.
  std::optional<Denial> onLogin7(const Login7& login);
  std::optional<Denial> onClientSspi(std::string_view token);
  // One complete server message while the login is pending.
  void onServerLoginMessage(const LoginResponseScan& scan);
  // The proxy refused the login.
  void setDenied() { result_ = LoginResult::Denied; }

  std::optional<LoginMethod> method() const { return method_; }
  // Who the client claims to be, once known; empty until then.
  const std::string& identity() const { return identity_; }
  LoginResult result() const { return result_; }
  // The server's error number when it refused the login.
  std::optional<uint32_t> serverError() const { return server_error_; }

private:
  std::optional<Denial> classify(std::string_view token);
  std::optional<Denial> check();

  std::shared_ptr<const AuthSettings> settings_;
  std::optional<LoginMethod> method_;
  std::string identity_;
  LoginResult result_ = LoginResult::Pending;
  std::optional<uint32_t> server_error_;
};

} // namespace MssqlProxy

#include "auth.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <format>

#include "ntlm.h"

namespace MssqlProxy {

namespace {

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
  return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char x, char y) {
    return std::tolower(static_cast<unsigned char>(x)) ==
           std::tolower(static_cast<unsigned char>(y));
  });
}

constexpr uint16_t kKrb5ApReq = 0x0100; // GSS TOK_ID of an AP-REQ (RFC 4121).

std::string loginFailed(std::string_view user) {
  return std::format("Login failed for user '{}'.", user);
}

} // namespace

const char* loginMethodName(LoginMethod method) {
  switch (method) {
  case LoginMethod::Sql:
    return "sql";
  case LoginMethod::Kerberos:
    return "kerberos";
  case LoginMethod::Ntlm:
    return "ntlm";
  case LoginMethod::Integrated:
    return "integrated";
  case LoginMethod::Federated:
    return "federated";
  }
  return "unknown";
}

const char* loginResultName(LoginResult result) {
  switch (result) {
  case LoginResult::Pending:
    return "pending";
  case LoginResult::Succeeded:
    return "succeeded";
  case LoginResult::Failed:
    return "failed";
  case LoginResult::Denied:
    return "denied";
  }
  return "unknown";
}

LoginAuth::LoginAuth(std::shared_ptr<const AuthSettings> settings)
    : settings_(settings ? std::move(settings) : std::make_shared<const AuthSettings>()) {}

std::optional<Denial> LoginAuth::onLogin7(const Login7& login) {
  if (!login.integrated) {
    // A federated login (fExtension with a FEDAUTH feature) carries no user
    // name either; without parsing the extension, an empty name says so.
    method_ = login.has_extension && login.user_name.empty() ? LoginMethod::Federated
                                                             : LoginMethod::Sql;
    identity_ = login.user_name;
    return check();
  }
  method_ = LoginMethod::Integrated;
  if (!login.has_sspi) {
    return check();
  }
  return classify(login.sspi);
}

std::optional<Denial> LoginAuth::onClientSspi(std::string_view token) {
  if (!method_ || *method_ == LoginMethod::Sql || *method_ == LoginMethod::Federated) {
    return std::nullopt; // Not an integrated login: nothing to learn.
  }
  return classify(token);
}

std::optional<Denial> LoginAuth::classify(std::string_view token) {
  std::string error;
  std::optional<AuthToken> parsed = parseAuthToken(token, error);
  // A later token without a mechanism of its own (e.g. a bare SPNEGO
  // continuation) keeps the method already known.
  if (parsed && parsed->mechanism != AuthMechanism::Unknown) {
    method_ = parsed->mechanism == AuthMechanism::Kerberos ? LoginMethod::Kerberos
                                                           : LoginMethod::Ntlm;
  }
  if (parsed && parsed->mechanism == AuthMechanism::Kerberos && settings_->kerberos &&
      parsed->krb5_tok_id == kKrb5ApReq && kerberos_principal_.empty()) {
    std::optional<KerberosTicketInfo> ticket =
        settings_->kerberos->read(parsed->inner, static_cast<int64_t>(std::time(nullptr)), error);
    if (!ticket) {
      // Fails closed: the proxy was told to know who logs in with Kerberos.
      return Denial{"Kerberos ticket not accepted: " + error, loginFailed("")};
    }
    kerberos_principal_ = ticket->client;
    identity_ = ticket->client;
  }
  if (parsed && parsed->mechanism == AuthMechanism::Ntlm &&
      ntlmMessageType(parsed->inner) == kNtlmAuthenticate) {
    std::optional<NtlmAuthenticate> authenticate = parseNtlmAuthenticate(parsed->inner, error);
    if (!authenticate) {
      // Fails closed: the server might read the message differently.
      return Denial{error, loginFailed("")};
    }
    identity_ = ntlmIdentity(*authenticate);
    if (authenticate->v1 && !settings_->ntlm_v1_allowed) {
      return Denial{std::format("NTLMv1 login of {} refused", identity_), loginFailed(identity_)};
    }
  }
  return check();
}

std::optional<Denial> LoginAuth::check() {
  if (method_ && !settings_->ntlm_allowed &&
      (*method_ == LoginMethod::Ntlm || *method_ == LoginMethod::Integrated)) {
    // Fails closed: an unrecognised mechanism could be NTLM.
    return Denial{std::format("{} login refused: NTLM is not allowed", loginMethodName(*method_)),
                  loginFailed(identity_)};
  }
  if (!identity_.empty()) {
    for (const std::string& denied : settings_->deny) {
      if (equalsIgnoreCase(identity_, denied)) {
        return Denial{std::format("login of {} refused by the deny list", identity_),
                      loginFailed(identity_)};
      }
    }
  }
  return std::nullopt;
}

void LoginAuth::onServerLoginMessage(const LoginResponseScan& scan) {
  if (result_ != LoginResult::Pending) {
    return;
  }
  if (scan.login_ack) {
    result_ = LoginResult::Succeeded;
  } else if (scan.error) {
    result_ = LoginResult::Failed;
    server_error_ = scan.error;
  }
}

} // namespace MssqlProxy

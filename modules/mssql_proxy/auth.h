#pragma once

// Follows one connection's login: how the client authenticates, who it
// claims to be, the allow/deny policy, and the server's verdict. Fed by the
// TLS bridge with the plain-text login messages. No Envoy dependency.
//
// Identities are claims until the server accepts the login (LOGINACK); the
// policy only ever denies on them, which a false claim can't exploit.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gss_token.h"
#include "login7.h"
#include "tds.h"

namespace MssqlProxy {

// What a Kerberos service ticket says about the client, once decrypted.
struct KerberosTicketInfo {
  std::string client;  // Principal, e.g. "alice@EXAMPLE.COM" (krb5 display form).
  std::string service; // The ticket's service principal, e.g. "MSSQLSvc/sql:1433@EXAMPLE.COM".
  int64_t endtime = 0; // Ticket expiry, seconds since the epoch.
};

// Reads the client's identity from an AP-REQ (kerberos.h implements it with
// the service keytab). Thread-safe.
class TicketReader {
public:
  virtual ~TicketReader() = default;
  // ap_req is the Kerberos message after the GSS framing; now is the time to
  // check the ticket and authenticator against. nullopt and error set when the
  // AP-REQ can't be read or doesn't hold.
  virtual std::optional<KerberosTicketInfo> read(std::string_view ap_req, int64_t now,
                                                 std::string& error) const = 0;
};

// Kerberos terminate: one connection's two GSS-API exchanges, the client's
// with the proxy (the proxy accepts) and the proxy's with SQL Server (the
// proxy initiates). kerberos_terminate.h implements it with MIT Kerberos.
// Steps may block (the KDC is asked for tickets), so they run off the event
// loop, one at a time; the object is never used by two threads at once.
class KerberosExchange {
public:
  struct Step {
    std::string token;     // For the peer; may be empty.
    bool complete = false; // This leg is established.
    std::string error;     // Set when the leg failed.
  };
  virtual ~KerberosExchange() = default;
  // The client's tokens, as sent (SPNEGO or bare Kerberos). binding: channel
  // binding application data for the client's leg, empty for none.
  virtual Step accept(std::string_view token, std::string_view binding) = 0;
  // The client's principal, e.g. "alice@EXAMPLE.COM", once accept completed.
  virtual std::string clientPrincipal() const = 0;
  // Toward the server's SPN: first with an empty token, then with each token
  // the server sends back (SPNEGO). Tokens returned are SPNEGO.
  virtual Step initiate(std::string_view token, const std::string& spn,
                        std::string_view binding) = 0;
};

class KerberosTerminator {
public:
  virtual ~KerberosTerminator() = default;
  virtual std::shared_ptr<KerberosExchange> start() const = 0;
};

// Channel binding for both Kerberos legs under terminate (RFC 5929): none, or
// a hash of the TLS server certificate of each leg (the proxy's toward the
// client, SQL Server's toward the server).
enum class ChannelBinding { None, TlsServerEndPoint };

struct KerberosTerminate {
  std::shared_ptr<const KerberosTerminator> terminator;
  std::string spn; // SQL Server's SPN, unless the routed cluster has its own.
  std::vector<std::pair<std::string, std::string>> cluster_spns; // (cluster, SPN)
  ChannelBinding channel_binding = ChannelBinding::None;

  // The SPN for a routed cluster (empty: not routed).
  const std::string& spnFor(std::string_view cluster) const;
};

struct AuthSettings {
  // NTLM logins pass through (the server verifies them), or are refused.
  bool ntlm_allowed = true;
  // NTLMv1 responses (24 bytes) pass through, or are refused.
  bool ntlm_v1_allowed = true;
  // Identities refused before the server is asked, compared ignoring ASCII
  // case: SQL login names; for NTLM "DOMAIN\user" with the domain as the client
  // sent it (NetBIOS or DNS name), or the bare user name it sent (e.g. a UPN).
  std::vector<std::string> deny;
  // Kerberos read_ticket: learn the client principal from the ticket. Null:
  // Kerberos logins pass through unread.
  std::shared_ptr<const TicketReader> kerberos;
  // Kerberos terminate: the proxy authenticates the client and logs in to the
  // server with its own Kerberos exchange. Integrated logins other than NTLM
  // are terminated; NTLM follows ntlm_allowed.
  std::optional<KerberosTerminate> terminate;
};

// What a refused login's client is told, as SQL Server words it.
std::string loginFailedMessage(std::string_view user);

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

  // The client's LOGIN7 and its later SSPI messages (0x11). nullopt: forward,
  // or with terminating() hand the login to the Kerberos exchange.
  std::optional<Denial> onLogin7(const Login7& login);
  std::optional<Denial> onClientSspi(std::string_view token);
  // Kerberos terminate: the proxy authenticates this login itself.
  bool terminating() const { return terminating_; }
  // Kerberos terminate: the proxy accepted the client as principal.
  std::optional<Denial> onKerberosAccepted(const std::string& principal);
  // One complete server message while the login is pending.
  void onServerLoginMessage(const LoginResponseScan& scan);
  // The proxy refused the login.
  void setDenied() { result_ = LoginResult::Denied; }

  std::optional<LoginMethod> method() const { return method_; }
  // Who the client claims to be, once known; empty until then. For
  // Kerberos read_ticket the KDC-issued principal from the ticket.
  const std::string& identity() const { return identity_; }
  // The Kerberos principal read from the ticket; empty otherwise.
  const std::string& kerberosPrincipal() const { return kerberos_principal_; }
  LoginResult result() const { return result_; }
  // The server's error number when it refused the login.
  std::optional<uint32_t> serverError() const { return server_error_; }

private:
  std::optional<Denial> classify(std::string_view token);
  std::optional<Denial> check();

  std::shared_ptr<const AuthSettings> settings_;
  std::optional<LoginMethod> method_;
  std::string identity_;
  std::string kerberos_principal_;
  LoginResult result_ = LoginResult::Pending;
  std::optional<uint32_t> server_error_;
  bool terminating_ = false;
};

} // namespace MssqlProxy

#pragma once

// The filter's filter_config: JSON, given either as a google.protobuf.Struct or
// as a StringValue holding JSON. No Envoy dependency.
//
//   {
//     "tls": {                              // Omit to only observe (no TLS termination).
//       "cert_file": "/etc/mssql_proxy/proxy.pem",  // Chain presented to clients, leaf first.
//       "key_file": "/etc/mssql_proxy/proxy.key",
//       "upstream_ca_file": "/etc/mssql_proxy/sql-ca.pem",  // CAs, or the server's own certificate.
//       "upstream_server_name": "sql.example.com",  // SNI and name check; optional.
//       "upstream_verify": true                     // Default true; false skips verification.
//     },
//     "routing": {                          // Pick the server from LOGIN7; needs "tls".
//       "routes": [                         // First match wins.
//         {"match": {"database": "sales"}, "cluster": "sql_sales"},
//         {"match": {"user": "etl", "app_name": "loader"}, "cluster": "sql_batch"}
//       ]
//     },
//     "auth": {                             // Login policy; needs "tls".
//       "ntlm": "pass_through",             // Or "v2_only", "deny"; default pass_through.
//       "deny": ["sa", "CORP\\svc_old"],    // Identities refused with error 18456.
//       "kerberos": {                       // Omit to relay Kerberos logins unread.
//         "mode": "read_ticket",
//         "keytab_file": "/etc/mssql_proxy/mssql.keytab"  // The SQL Server service's keys.
//       }
//     }
//   }
//
// With "routing", the module answers PRELOGIN itself and connects to the
// server only once it has read LOGIN7 (tcp_proxy must use
// upstream_connect_mode ON_DOWNSTREAM_DATA with delayed route selection).
// Route matches compare LOGIN7 fields exactly, ignoring ASCII case; every
// field given must match, and an empty match matches everything. Keys:
// database, user, server_name, app_name, client_host, library, principal
// (the Kerberos client principal, with auth.kerberos). A login no
// route matches goes to tcp_proxy's own cluster.
//
// "auth" applies to every TDS 7.x login the module reads (see auth.h): logins
// it refuses are answered with error 18456 and never reach the server. NTLM
// passes through unchanged and the server verifies it; the module reads the
// claimed user from AUTHENTICATE ("DOMAIN\\user" in deny entries). "v2_only"
// refuses NTLMv1 responses. With "ntlm": "deny", integrated logins whose
// mechanism isn't recognised are refused too, since they could be NTLM.
// With "kerberos" "read_ticket", the module decrypts each Kerberos login's
// service ticket with the keytab to learn the client principal (see
// kerberos.h); a ticket it can't read is refused. Route matches can then use
// "principal" (e.g. "alice@EXAMPLE.COM"), and deny entries name principals.
//
// Unknown keys are rejected, so a typo can't silently disable a setting.

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "auth.h"
#include "login7.h"
#include "tls_bridge.h"

namespace MssqlProxy {

struct Route {
  // (LOGIN7 field, value) pairs that must all match.
  std::vector<std::pair<std::string, std::string>> match;
  std::string cluster;
};

struct RoutingConfig {
  std::vector<Route> routes;
};

struct KerberosConfig {
  std::string keytab_path; // read_ticket: the service's keytab.
};

struct FilterConfig {
  // Set when TLS is terminated; otherwise the filter only observes.
  std::optional<TlsSettings> tls;
  // Set when the server is picked from LOGIN7.
  std::optional<RoutingConfig> routing;
  // Set when a login policy is configured.
  std::optional<AuthSettings> auth;
  // Set with auth.kerberos (the reader is made from it at load time).
  std::optional<KerberosConfig> kerberos;
};

// The first route whose match fits the login, or nullptr. principal: the
// Kerberos client principal, empty when not known.
const Route* selectRoute(const RoutingConfig& routing, const Login7& login,
                         std::string_view principal = {});

// Reads a whole file; returns nullopt and sets error on failure.
using FileReader = std::function<std::optional<std::string>(const std::string& path,
                                                            std::string& error)>;

std::optional<std::string> readFile(const std::string& path, std::string& error);

// Parses the filter config, reading the files it names with read_file. An
// empty config means the defaults.
std::optional<FilterConfig> parseFilterConfig(std::string_view json, const FileReader& read_file,
                                              std::string& error);

} // namespace MssqlProxy

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
//     }
//   }
//
// With "routing", the module answers PRELOGIN itself and connects to the
// server only once it has read LOGIN7 (tcp_proxy must use
// upstream_connect_mode ON_DOWNSTREAM_DATA with delayed route selection).
// Route matches compare LOGIN7 fields exactly, ignoring ASCII case; every
// field given must match, and an empty match matches everything. Keys:
// database, user, server_name, app_name, client_host, library. A login no
// route matches goes to tcp_proxy's own cluster.
//
// Unknown keys are rejected, so a typo can't silently disable a setting.

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

struct FilterConfig {
  // Set when TLS is terminated; otherwise the filter only observes.
  std::optional<TlsSettings> tls;
  // Set when the server is picked from LOGIN7.
  std::optional<RoutingConfig> routing;
};

// The first route whose match fits the login, or nullptr.
const Route* selectRoute(const RoutingConfig& routing, const Login7& login);

// Reads a whole file; returns nullopt and sets error on failure.
using FileReader = std::function<std::optional<std::string>(const std::string& path,
                                                            std::string& error)>;

std::optional<std::string> readFile(const std::string& path, std::string& error);

// Parses the filter config, reading the files it names with read_file. An
// empty config means the defaults.
std::optional<FilterConfig> parseFilterConfig(std::string_view json, const FileReader& read_file,
                                              std::string& error);

} // namespace MssqlProxy

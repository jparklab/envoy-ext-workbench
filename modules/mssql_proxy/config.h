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
//     }
//   }
//
// Unknown keys are rejected, so a typo can't silently disable a setting.

#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "tls_bridge.h"

namespace MssqlProxy {

struct FilterConfig {
  // Set when TLS is terminated; otherwise the filter only observes.
  std::optional<TlsSettings> tls;
};

// Reads a whole file; returns nullopt and sets error on failure.
using FileReader = std::function<std::optional<std::string>(const std::string& path,
                                                            std::string& error)>;

std::optional<std::string> readFile(const std::string& path, std::string& error);

// Parses the filter config, reading the files it names with read_file. An
// empty config means the defaults.
std::optional<FilterConfig> parseFilterConfig(std::string_view json, const FileReader& read_file,
                                              std::string& error);

} // namespace MssqlProxy

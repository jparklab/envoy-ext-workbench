#pragma once

// LOGIN7 (MS-TDS 2.2.6.4): the client's login, sent after PRELOGIN (and the
// TLS handshake, when encrypting). No Envoy dependency.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace MssqlProxy {

// What the proxy reads from a LOGIN7. Strings are converted from UTF-16LE to
// UTF-8. The password is never decoded.
struct Login7 {
  uint32_t tds_version = 0;
  uint32_t packet_size = 0;   // Requested; 0 means the server's default.
  bool integrated = false;    // fIntSecurity: Windows (SSPI) authentication.
  bool has_sspi = false;      // SSPI data present in the LOGIN7 itself.
  bool has_extension = false; // fExtension: feature extensions (e.g. federated auth).
  std::string host_name;      // Client machine.
  std::string user_name;      // SQL login; empty with integrated authentication.
  std::string app_name;
  std::string server_name;    // As the client was told to reach the server.
  std::string library_name;   // Client interface, e.g. "ODBC".
  std::string language;
  std::string database;       // Initial database; empty for the login's default.
  std::string sspi;           // SSPI data: the client's first authentication token.
};

// Largest LOGIN7 message accepted (MS-TDS caps it at 128 KB).
inline constexpr size_t kMaxLogin7Size = 128 * 1024;

// Parses a LOGIN7 message payload (all packets concatenated, headers removed).
// Every offset and length is bounds-checked. Returns nullopt and sets error on
// malformed input.
std::optional<Login7> parseLogin7(std::string_view payload, std::string& error);

// The LOGIN7 payload with its SSPI data replaced by sspi, for logging in to
// the server with the proxy's own token (Kerberos terminate). Everything else
// stays as the client sent it: the data after the SSPI data moves, and with it
// every offset pointing there (the feature extension's too); cbSSPI,
// cbSSPILong and Length are updated. nullopt and error set when the payload is
// malformed or sspi doesn't fit.
std::optional<std::string> replaceLogin7Sspi(std::string_view payload, std::string_view sspi,
                                             std::string& error);

// UTF-16LE to UTF-8; unpaired surrogates become U+FFFD.
std::string utf16leToUtf8(std::string_view utf16le);

} // namespace MssqlProxy

#pragma once

// The Kerberos (RFC 4120) messages the proxy reads, parsed from DER without a
// Kerberos library: the client's AP-REQ, which carries the ticket for the
// service and the authenticator, and the authenticator once decrypted.
// Decryption itself is in kerberos.h. No Envoy dependency.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace MssqlProxy {

struct KrbPrincipalName {
  int32_t type = 0;
  std::vector<std::string> components;
};

// "comp1/comp2@REALM". Components and realm are shown as sent (no escaping:
// for logs and comparisons within the proxy).
std::string principalString(const KrbPrincipalName& name, std::string_view realm);

struct KrbEncryptedData {
  int32_t etype = 0;
  std::optional<uint32_t> kvno;
  std::string_view cipher;
};

struct KrbApReq {
  uint32_t ap_options = 0;     // First 32 bits of the options (bit 0 is the MSB).
  std::string_view ticket;     // The whole Ticket ([APPLICATION 1]), for decoding.
  std::string ticket_realm;    // The service's realm and name, from the Ticket's
  KrbPrincipalName ticket_sname; // plain-text part.
  KrbEncryptedData authenticator;
};

// Views into der; nullopt and error set when malformed.
std::optional<KrbApReq> parseApReq(std::string_view der, std::string& error);

struct KrbAuthenticator {
  std::string crealm;
  KrbPrincipalName cname;
  int64_t ctime = 0; // Seconds since the epoch.
  uint32_t cusec = 0;
};

// A decrypted authenticator ([APPLICATION 2]). Trailing bytes after it (block
// padding left by some enctypes) are ignored.
std::optional<KrbAuthenticator> parseAuthenticator(std::string_view der, std::string& error);

} // namespace MssqlProxy

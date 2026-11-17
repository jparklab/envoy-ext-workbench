#pragma once

// Kerberos read_ticket: the client principal from the AP-REQ in a login,
// learned by decrypting the service ticket with the service's keytab and
// checking the authenticator with the ticket's session key. Nothing is
// recorded in a replay cache: the AP-REQ goes on to SQL Server unchanged, and
// its own replay check sees it once. No Envoy dependency.
//
// What this establishes: the ticket was issued by the KDC for a service whose
// key is in the keytab, to the principal it names, and the authenticator was
// made with its session key within the clock skew. A replay of a captured
// AP-REQ within the skew passes here but is refused by the server.

#include <memory>
#include <string>

#include "auth.h"

namespace MssqlProxy {

// Allowed difference between the proxy's clock and the KDC's or the client's
// (the Kerberos default).
inline constexpr int64_t kKerberosClockSkew = 300;

class KeytabTicketReader : public TicketReader {
public:
  // Checks that the keytab file has keys; nullptr (error set) otherwise. The
  // keytab is reread on use, so it can be rotated.
  static std::shared_ptr<const KeytabTicketReader> create(const std::string& keytab_path,
                                                          std::string& error);

  std::optional<KerberosTicketInfo> read(std::string_view ap_req, int64_t now,
                                         std::string& error) const override;

private:
  explicit KeytabTicketReader(std::string keytab_name) : keytab_name_(std::move(keytab_name)) {}

  std::string keytab_name_; // "FILE:<path>"
};

} // namespace MssqlProxy

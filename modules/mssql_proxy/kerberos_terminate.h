#pragma once

// Kerberos terminate with MIT GSS-API: the proxy accepts each client's
// Kerberos login with its own service keys, then logs in to SQL Server with a
// Kerberos exchange of its own, as the client (delegation) or as itself (a
// service account). No Envoy dependency.
//
// - Acceptor: the proxy's keytab (its SPN, e.g. MSSQLSvc/proxy:1433), any
//   principal in it; SPNEGO or bare Kerberos; MIT's replay cache stays on,
//   since the client's ticket never travels further.
// - service_account: the proxy's own principal from its client keytab, with
//   tickets cached in a memory ccache per terminator (refreshed by MIT).
// - delegate: the client's credentials. A client that forwards its TGT
//   (delegation flag) hands them over directly. Otherwise the acceptor also
//   initiates (GSS_C_BOTH), so MIT turns the client's forwardable ticket into
//   evidence for S4U2Proxy (constrained delegation), requested with the
//   proxy's own TGT: that of TerminateOptions::principal from its client
//   keytab, else the first principal of the service keytab (its SPN). The KDC
//   must allow that principal's account to delegate to SQL Server's SPN, and
//   give it a TGT (AD gives none to an SPN: name the account). MIT looks the
//   evidence ticket up under that principal but names it after the principal
//   that decrypted it, so with one named the proxy accepts with that
//   principal's keys too (first), then the service keytab's.
// - Toward the server: Kerberos with mutual authentication, wrapped in SPNEGO
//   offering Kerberos alone, as Windows clients send it.

#include <memory>
#include <mutex>
#include <string>

#include "auth.h"

namespace MssqlProxy {

struct TerminateOptions {
  // The proxy's service keys: for accepting clients, and with delegate (and
  // no client keytab) for the proxy's own TGT (constrained delegation).
  std::string keytab_path;
  bool delegate = false; // Log in to the server as the client.
  // service_account: the keys of the account the proxy logs in as (required).
  // delegate: the keys the proxy's own TGT is had with; empty for keytab_path.
  std::string client_keytab_path;
  // The principal to log in as (service_account), or to take the proxy's own
  // TGT as (delegate); empty for the keytab's first (delegate: of
  // client_keytab_path, else of keytab_path, as before). An AD KDC doesn't
  // give a TGT to an SPN, so there it is the service account.
  std::string principal;
};

class GssTerminator : public KerberosTerminator,
                      public std::enable_shared_from_this<GssTerminator> {
public:
  // Checks the keytabs and acquires the credentials. nullptr (error set) on
  // failure. Keytabs are reread on use, so they can be rotated.
  static std::shared_ptr<const GssTerminator> create(const TerminateOptions& options,
                                                     std::string& error);
  ~GssTerminator() override;

  std::shared_ptr<KerberosExchange> start() const override;

  struct Creds; // gss_cred_id_t handles; kerberos_terminate.cc.

  // delegate: makes sure the proxy's own TGT, as its service principal, is
  // in its memory ccache (fetched with the keytab, renewed before it
  // expires); MIT takes it into the S4U2Proxy credential when it accepts a
  // client that forwarded no TGT. May ask the KDC: worker threads only. False
  // (error set) when it can't be had.
  bool ensureProxyTgt(std::string& error) const;
  bool needsProxyTgt() const { return delegate_; }

private:
  GssTerminator() = default;

  bool delegate_ = false;
  std::string tgt_keytab_;      // delegate: "FILE:<path>" of the keys the TGT is had with.
  std::string tgt_principal_;   // delegate: whose TGT; empty for tgt_keytab_'s first.
  // delegate with a principal or client keytab named: the keytab the proxy
  // accepts clients with, "MEMORY:<name>", holds that principal's keys from
  // tgt_keytab_ and then all of service_keytab_ ("FILE:<path>"), refilled when
  // either file changes. MIT names the evidence ticket for S4U2Proxy after
  // the principal that decrypted it, and looks it up under the one the TGT is
  // for, so the proxy must accept as the account (AD gives it the SPN's keys).
  std::string service_keytab_;
  std::string acceptor_keytab_;
  mutable std::string acceptor_stamp_; // Of the two files last read.
  std::string ccache_;        // "MEMORY:<name>".
  std::unique_ptr<Creds> creds_;
  mutable std::mutex tgt_mutex_;
};

} // namespace MssqlProxy

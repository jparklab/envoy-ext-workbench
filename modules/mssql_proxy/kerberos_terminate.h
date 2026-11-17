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
//   initiates (GSS_C_BOTH) with the same keytab, so MIT turns the client's
//   forwardable ticket into evidence for S4U2Proxy (constrained delegation),
//   requested as the proxy's service principal with that principal's TGT; the
//   KDC must allow the proxy's account to delegate to SQL Server's SPN.
// - Toward the server: Kerberos with mutual authentication, wrapped in SPNEGO
//   offering Kerberos alone, as Windows clients send it.

#include <memory>
#include <mutex>
#include <string>

#include "auth.h"

namespace MssqlProxy {

struct TerminateOptions {
  // The proxy's service keys: for accepting clients, and with delegate for
  // the proxy's own TGT (constrained delegation).
  std::string keytab_path;
  bool delegate = false; // Log in to the server as the client.
  // service_account: the keys of the account the proxy logs in as.
  std::string client_keytab_path;
  // service_account: the principal to log in as; empty for the client
  // keytab's first.
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
  std::string tgt_keytab_; // delegate: "FILE:<path>" of the service keys.
  std::string ccache_;        // "MEMORY:<name>".
  std::unique_ptr<Creds> creds_;
  mutable std::mutex tgt_mutex_;
};

} // namespace MssqlProxy

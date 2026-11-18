// Kerberos terminate end to end, against the throwaway MIT KDC
// (testdata/mit_kdc.sh): alice logs in through the TlsBridge with a real GSS
// initiator; the proxy (GssTerminator) accepts her with its own SPN's keys
// and logs in to a stand-in SQL Server, a real GSS acceptor with the server's
// keys, which checks whom it sees. Skipped when the MIT KDC tools are missing.

#include "kerberos_terminate.h"

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#include "bridge_test_util.h"
#include "gtest/gtest.h"
#include "kdc_test_util.h"
#include "login7.h"
#include "tds.h"
#include "test_util.h"

namespace MssqlProxy {
namespace {

using namespace test;

constexpr const char* kProxySpn = "MSSQLSvc/proxy.test:1433";
constexpr const char* kServerSpn = "MSSQLSvc/sql.test:1433";

gss_OID_desc kSpnego{6, const_cast<char*>("\x2b\x06\x01\x05\x05\x02")};

gss_buffer_desc bufferOf(std::string_view s) { return {s.size(), const_cast<char*>(s.data())}; }

std::string take(gss_buffer_desc& b) {
  std::string s(static_cast<const char*>(b.value), b.length);
  OM_uint32 minor;
  gss_release_buffer(&minor, &b);
  return s;
}

gss_cred_id_t acquire(gss_cred_usage_t usage, const char* key, const std::string& value) {
  gss_key_value_element_desc element{key, value.c_str()};
  gss_key_value_set_desc store{1, &element};
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  OM_uint32 minor;
  EXPECT_FALSE(GSS_ERROR(gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                               GSS_C_NO_OID_SET, usage, &store, &cred, nullptr,
                                               nullptr)));
  return cred;
}

struct Bindings {
  explicit Bindings(const std::string& data) {
    if (!data.empty()) {
      cb.application_data = bufferOf(data);
    }
  }
  gss_channel_bindings_t get() {
    return cb.application_data.length == 0 ? GSS_C_NO_CHANNEL_BINDINGS : &cb;
  }
  gss_channel_bindings_struct cb{};
};

// alice, as a Windows-like client: SPNEGO, mutual authentication.
class Client {
public:
  // ccache: alice's credential cache; by default the one in the KDC's directory.
  Client(const std::string& kdc_dir, const char* spn, OM_uint32 flags, std::string binding = {},
         const std::string& ccache = {})
      : flags_(flags), binding_(std::move(binding)) {
    cred_ = acquire(GSS_C_INITIATE, "ccache",
                    "FILE:" + (ccache.empty() ? kdc_dir + "/alice.ccache" : ccache));
    gss_buffer_desc name = bufferOf(spn);
    OM_uint32 minor;
    EXPECT_FALSE(GSS_ERROR(gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &target_)));
  }
  ~Client() {
    OM_uint32 minor;
    gss_delete_sec_context(&minor, &ctx_, GSS_C_NO_BUFFER);
    gss_release_name(&minor, &target_);
    gss_release_cred(&minor, &cred_);
  }

  // The first token, or with input the next step; major status in status.
  std::string step(std::string_view input = {}) {
    gss_buffer_desc in = bufferOf(input);
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
    Bindings bindings(binding_);
    OM_uint32 minor;
    status = gss_init_sec_context(&minor, cred_, &ctx_, target_, &kSpnego, flags_, 0,
                                  bindings.get(), input.empty() ? GSS_C_NO_BUFFER : &in, nullptr,
                                  &out, nullptr, nullptr);
    return take(out);
  }

  OM_uint32 status = 0;

private:
  OM_uint32 flags_;
  std::string binding_;
  gss_cred_id_t cred_ = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t ctx_ = GSS_C_NO_CONTEXT;
  gss_name_t target_ = GSS_C_NO_NAME;
};

// The SQL Server's side: a GSS acceptor with the server's keys.
struct Server {
  explicit Server(const std::string& kdc_dir) {
    cred = acquire(GSS_C_ACCEPT, "keytab", "FILE:" + kdc_dir + "/service.keytab");
  }
  ~Server() {
    OM_uint32 minor;
    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    gss_release_cred(&minor, &cred);
  }
  // Accepts token; sets who on completion.
  std::string accept(std::string_view token, const std::string& binding = {}) {
    gss_buffer_desc in = bufferOf(token);
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
    gss_name_t source = GSS_C_NO_NAME;
    Bindings bindings(binding);
    OM_uint32 minor;
    status = gss_accept_sec_context(&minor, &ctx, cred, &in, bindings.get(), &source, nullptr,
                                    &out, nullptr, nullptr, nullptr);
    if (status == GSS_S_COMPLETE) {
      gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
      gss_display_name(&minor, source, &name, nullptr);
      who = take(name);
    }
    gss_release_name(&minor, &source);
    return take(out);
  }
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  OM_uint32 status = 0;
  std::string who;
};

// The payload of a TDS message (its packets' payloads joined).
std::string payloadOf(std::string_view message) {
  std::string out;
  while (message.size() >= kTdsHeaderSize) {
    const size_t len = (static_cast<uint8_t>(message[2]) << 8) | static_cast<uint8_t>(message[3]);
    out += message.substr(kTdsHeaderSize, len - kTdsHeaderSize);
    message.remove_prefix(len);
  }
  return out;
}

std::string endPoint(const std::string& cert_pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
  bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  uint8_t hash[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EXPECT_TRUE(X509_digest(cert.get(), EVP_sha256(), hash, &len));
  return "tls-server-end-point:" + std::string(reinterpret_cast<char*>(hash), len);
}

class Terminate : public ThrowawayKdc {
protected:
  std::shared_ptr<const AuthSettings> settings(bool delegate,
                                               ChannelBinding binding = ChannelBinding::None) {
    return settings(TerminateOptions{.keytab_path = dir_ + "/proxy.keytab",
                                     .delegate = delegate,
                                     .client_keytab_path =
                                         delegate ? "" : dir_ + "/svc-proxy.keytab"},
                    binding);
  }

  std::shared_ptr<const AuthSettings> settings(const TerminateOptions& options,
                                               ChannelBinding binding = ChannelBinding::None) {
    std::string error;
    auto terminator = GssTerminator::create(options, error);
    EXPECT_TRUE(terminator) << error;
    AuthSettings s;
    s.terminate = KerberosTerminate{
        .terminator = terminator, .spn = kServerSpn, .channel_binding = binding};
    return std::make_shared<const AuthSettings>(std::move(s));
  }

  // What the KDC logged since from (a size from kdcLogSize()).
  size_t kdcLogSize() const {
    std::ifstream in(dir_ + "/kdc.log", std::ios::binary | std::ios::ate);
    return in ? static_cast<size_t>(in.tellg()) : 0;
  }
  std::string kdcLogSince(size_t from) const {
    std::ifstream in(dir_ + "/kdc.log", std::ios::binary);
    in.seekg(static_cast<std::streamoff>(from));
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  }

  // alice's LOGIN7 through the bridge; the server's half if it gets that far.
  // Returns the bridge's error, if any.
  std::optional<BridgeError> login(Harness& h, Client& client, Server& server,
                                   const std::string& server_binding = {}) {
    EXPECT_TRUE(h.connect()) << h.message();
    Login7Fields f;
    f.user = "";
    f.integrated = true;
    f.sspi = client.step();
    EXPECT_EQ(client.status, GSS_S_CONTINUE_NEEDED);
    h.client.send(kTdsLogin7, login7Payload(f), true);
    if (!h.pump()) {
      return h.error;
    }
    std::string error;
    auto upstream = parseLogin7(payloadOf(h.server.received), error);
    EXPECT_TRUE(upstream) << error;
    if (!upstream) {
      return std::nullopt;
    }
    EXPECT_EQ(upstream->database, "master") << "the rest of LOGIN7 as the client sent it";
    const std::string answer = server.accept(upstream->sspi, server_binding);
    EXPECT_EQ(server.status, GSS_S_COMPLETE);
    h.server.send(kTdsTabularResult, sspiToken(answer) + loginResponse("4096"), true);
    if (!h.pump()) {
      return h.error;
    }
    auto scan = scanLoginResponse(payloadOf(h.client.received), error);
    EXPECT_TRUE(scan && scan->login_ack && scan->sspi) << error;
    if (scan && scan->sspi) {
      client.step(*scan->sspi);
    }
    return std::nullopt;
  }
};

TEST_F(Terminate, ServiceAccount) {
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(false)});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG);
  Server server(dir_);
  ASSERT_FALSE(login(h, alice, server)) << h.message();
  EXPECT_EQ(server.who, "svc-proxy@TEST.REALM") << "the server sees the proxy's account";
  EXPECT_EQ(h.bridge.auth().identity(), "alice@TEST.REALM") << "the proxy knows the user";
  EXPECT_EQ(alice.status, GSS_S_COMPLETE) << "the client authenticated the proxy";
  EXPECT_EQ(h.bridge.auth().result(), LoginResult::Succeeded);
}

TEST_F(Terminate, DelegateWithAForwardedTicket) {
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(true)});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
  Server server(dir_);
  ASSERT_FALSE(login(h, alice, server)) << h.message();
  EXPECT_EQ(server.who, "alice@TEST.REALM") << "the server sees the user";
  EXPECT_EQ(alice.status, GSS_S_COMPLETE);
}

// Without a forwarded TGT, the proxy asks for constrained delegation
// (S4U2Proxy) as its own SPN principal. This realm's database (DB2) can't
// allow that, so the KDC refuses and so does the proxy.
TEST_F(Terminate, ConstrainedDelegationTheKdcRefusesIsRefused) {
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(true)});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG);
  Server server(dir_);
  auto error = login(h, alice, server);
  ASSERT_TRUE(error);
  EXPECT_EQ(error->kind, BridgeError::Kind::Denied);
  EXPECT_NE(error->message.find("Kerberos login to the server failed"), std::string::npos)
      << error->message;
  EXPECT_TRUE(h.server.received.empty());
  std::cout << "constrained delegation: " << error->message << "\n";
}

// With no principal named, the proxy's own TGT is its SPN's, as it always was
// (an MIT KDC gives one; Samba AD and AD do not).
TEST_F(Terminate, DelegateTakesTheProxysTgtAsItsSpnByDefault) {
  const size_t log = kdcLogSize();
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(true)});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
  Server server(dir_);
  ASSERT_FALSE(login(h, alice, server)) << h.message();
  EXPECT_EQ(server.who, "alice@TEST.REALM");
  EXPECT_NE(kdcLogSince(log).find("MSSQLSvc/proxy.test:1433@TEST.REALM for krbtgt/TEST.REALM"),
            std::string::npos);
}

// A principal and keytab of their own for the proxy's TGT, the service keytab
// staying the acceptor's: the proxy still accepts with its SPN's keys, which
// don't hold the account's.
TEST_F(Terminate, DelegateAsAServiceAccountWithAForwardedTicket) {
  const size_t log = kdcLogSize();
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.auth = settings(TerminateOptions{
                              .keytab_path = dir_ + "/proxy.keytab",
                              .delegate = true,
                              .client_keytab_path = dir_ + "/svc-proxy.keytab",
                              .principal = "svc-proxy"})});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
  Server server(dir_);
  ASSERT_FALSE(login(h, alice, server)) << h.message();
  EXPECT_EQ(server.who, "alice@TEST.REALM") << "the server sees the user";
  EXPECT_EQ(alice.status, GSS_S_COMPLETE);
  const std::string logged = kdcLogSince(log);
  EXPECT_NE(logged.find("svc-proxy@TEST.REALM for krbtgt/TEST.REALM"), std::string::npos)
      << "the proxy's TGT is the account's\n" << logged;
  EXPECT_EQ(logged.find("MSSQLSvc/proxy.test:1433@TEST.REALM for krbtgt/TEST.REALM"),
            std::string::npos)
      << "not its SPN's\n" << logged;
}

// The same without a forwarded TGT: the proxy asks for constrained delegation
// as the account. This realm can't grant it (its database has no constrained
// delegation, and names alice's ticket after the SPN where MIT looks for it
// under the account's name; Samba AD and AD name it after the account, so
// there it works: tests/mssql_ad_terminate_test.sh), so the login is refused
// at the server leg whatever MIT's wording of why. What is checked is whose
// TGT the proxy held: the account's, from the KDC's log.
TEST_F(Terminate, ConstrainedDelegationIsAskedForAsTheNamedPrincipal) {
  const size_t log = kdcLogSize();
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.auth = settings(TerminateOptions{
                              .keytab_path = dir_ + "/proxy.keytab",
                              .delegate = true,
                              .client_keytab_path = dir_ + "/svc-proxy.keytab",
                              .principal = "svc-proxy"})});
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG);
  Server server(dir_);
  auto error = login(h, alice, server);
  ASSERT_TRUE(error);
  EXPECT_EQ(error->kind, BridgeError::Kind::Denied);
  EXPECT_NE(error->message.find("Kerberos login to the server failed"), std::string::npos)
      << error->message;
  EXPECT_TRUE(h.server.received.empty());
  const std::string logged = kdcLogSince(log);
  EXPECT_NE(logged.find("svc-proxy@TEST.REALM for krbtgt/TEST.REALM"), std::string::npos)
      << "the proxy held the account's TGT\n" << logged;
  EXPECT_EQ(logged.find("MSSQLSvc/proxy.test:1433@TEST.REALM for krbtgt/TEST.REALM"),
            std::string::npos)
      << "not its SPN's\n" << logged;
}

// MIT names the evidence ticket after the principal that decrypted it and
// looks it up under the account's name, so with an account named the proxy
// also accepts as the account (on AD its keys are the SPN's): a ticket sealed
// with the account's keys is taken, which the SPN's keytab alone can't.
TEST_F(Terminate, DelegateAlsoAcceptsAsTheNamedAccount) {
  {
    Harness h(kEncOn, kEncOn, 0, false, contexts(),
              BridgeOptions{.auth = settings(TerminateOptions{
                                .keytab_path = dir_ + "/proxy.keytab",
                                .delegate = true,
                                .client_keytab_path = dir_ + "/svc-proxy.keytab",
                                .principal = "svc-proxy"})});
    Client alice(dir_, "svc-proxy", GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
    Server server(dir_);
    ASSERT_FALSE(login(h, alice, server)) << h.message();
    EXPECT_EQ(server.who, "alice@TEST.REALM");
  }
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(true)});
  Client alice(dir_, "svc-proxy", GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
  Server server(dir_);
  auto error = login(h, alice, server);
  ASSERT_TRUE(error) << "the SPN's keytab alone has no keys for the account";
  EXPECT_NE(error->message.find("Kerberos login to the proxy failed"), std::string::npos)
      << error->message;
}

TEST_F(Terminate, DelegatePrincipalTheKeytabLacksIsRefusedAtCreation) {
  std::string error;
  EXPECT_FALSE(GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab",
                                      .delegate = true,
                                      .client_keytab_path = dir_ + "/svc-proxy.keytab",
                                      .principal = "nobody"},
                                     error));
  EXPECT_NE(error.find("the proxy's principal nobody"), std::string::npos) << error;
  // A client keytab alone: its first principal.
  EXPECT_TRUE(GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab",
                                     .delegate = true,
                                     .client_keytab_path = dir_ + "/svc-proxy.keytab"},
                                    error))
      << error;
  EXPECT_FALSE(GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab",
                                      .delegate = true,
                                      .client_keytab_path = dir_ + "/missing.keytab"},
                                     error));
}

// A TGT the KDC won't give at creation (here: the principal is in the keytab
// but not in the KDC; a KDC that is down for a moment is the same) doesn't
// refuse the config: it is warned of, and the login that needs it fails.
TEST_F(Terminate, TgtThatCantBeHadAtCreationIsOnlyAWarning) {
  std::string error;
  auto terminator = GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab",
                                           .delegate = true,
                                           .client_keytab_path = dir_ + "/ghost.keytab",
                                           .principal = "ghost"},
                                          error);
  ASSERT_TRUE(terminator) << error;
  EXPECT_NE(terminator->startupWarning().find("TGT"), std::string::npos)
      << terminator->startupWarning();
}

// Replaces dst with src in one step, as a keytab rotation tool does.
void replaceFile(const std::string& src, const std::string& dst) {
  std::filesystem::copy_file(src, dst + ".new", std::filesystem::copy_options::overwrite_existing);
  std::filesystem::rename(dst + ".new", dst);
}

// The keytab the proxy accepts with changes between logins, as in a key
// rotation: the next login is accepted with the new keys, and the old ones
// are gone.
TEST_F(Terminate, ServiceKeytabRotationIsPickedUpBetweenLogins) {
  const std::string live = dir_ + "/live.keytab";
  replaceFile(dir_ + "/proxy.keytab", live);
  auto auth = settings(TerminateOptions{.keytab_path = live,
                                        .delegate = true,
                                        .client_keytab_path = dir_ + "/svc-proxy.keytab",
                                        .principal = "svc-proxy"});
  auto login_to = [&](const char* spn) -> std::optional<BridgeError> {
    Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = auth});
    Client alice(dir_, spn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
    Server server(dir_);
    auto error = login(h, alice, server);
    if (!error) {
      EXPECT_EQ(server.who, "alice@TEST.REALM");
    }
    return error;
  };
  EXPECT_FALSE(login_to(kProxySpn)) << "the proxy's keys";
  EXPECT_TRUE(login_to("MSSQLSvc/other.test:1433")) << "not the keys of another service yet";

  replaceFile(dir_ + "/other.keytab", live); // Another service's keys, the proxy's gone.
  EXPECT_FALSE(login_to("MSSQLSvc/other.test:1433")) << "the new keys are used";
  auto gone = login_to(kProxySpn);
  ASSERT_TRUE(gone) << "the old keys are not";
  EXPECT_NE(gone->message.find("Kerberos login to the proxy failed"), std::string::npos)
      << gone->message;

  replaceFile(dir_ + "/proxy.keytab", live);
  EXPECT_FALSE(login_to(kProxySpn)) << "and back";
}

// A keytab that can't be read for a moment (replaced, or removed by a
// rotation tool) leaves logins on the keys they had.
TEST_F(Terminate, FailedRebuildKeepsTheKeysInUse) {
  const std::string live = dir_ + "/live2.keytab";
  replaceFile(dir_ + "/proxy.keytab", live);
  auto auth = settings(TerminateOptions{.keytab_path = live,
                                        .delegate = true,
                                        .client_keytab_path = dir_ + "/svc-proxy.keytab",
                                        .principal = "svc-proxy"});
  auto login_ok = [&]() {
    Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = auth});
    Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG);
    Server server(dir_);
    return !login(h, alice, server);
  };
  EXPECT_TRUE(login_ok());
  std::filesystem::remove(live);
  EXPECT_TRUE(login_ok()) << "the keytab is gone: the snapshot in use stays";
  {
    std::ofstream(live) << "not a keytab"; // Briefly unreadable garbage.
  }
  EXPECT_TRUE(login_ok()) << "so does a keytab that can't be read";
  replaceFile(dir_ + "/proxy.keytab", live);
  EXPECT_TRUE(login_ok()) << "and once it is whole again it is read again";
}

// Workers accept logins while the keytab file is replaced over and over, as
// in a rotation. Both versions hold the proxy's keys, so every login must be
// accepted: the keytab a login accepts with is never changed under it (the
// crash this guards against is a use after free in MIT's in-memory keytab;
// the number of threads and rounds is what makes it likely to show).
TEST_F(Terminate, ConcurrentLoginsWhileTheKeytabIsReplaced) {
  const std::string live = dir_ + "/live3.keytab";
  replaceFile(dir_ + "/proxy.keytab", live);
  std::string error;
  auto terminator = GssTerminator::create({.keytab_path = live,
                                           .delegate = true,
                                           .client_keytab_path = dir_ + "/svc-proxy.keytab",
                                           .principal = "svc-proxy"},
                                          error);
  ASSERT_TRUE(terminator) << error;

  constexpr int kThreads = 8;
  constexpr int kRounds = 100;
  std::atomic<bool> stop{false};
  std::atomic<int> accepted{0}, refused{0};
  std::thread rotator([&] {
    bool both = true;
    while (!stop) {
      replaceFile(dir_ + (both ? "/proxy-other.keytab" : "/proxy.keytab"), live);
      both = !both;
      std::this_thread::yield();
    }
  });
  std::vector<std::thread> workers;
  for (int t = 0; t < kThreads; ++t) {
    workers.emplace_back([&, t] {
      // A credential cache of its own: a file ccache is not for sharing.
      const std::string ccache = dir_ + "/worker" + std::to_string(t) + ".ccache";
      std::filesystem::copy_file(dir_ + "/alice.ccache", ccache,
                                 std::filesystem::copy_options::overwrite_existing);
      for (int i = 0; i < kRounds; ++i) {
        Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, {}, ccache);
        const std::string token = alice.step();
        auto exchange = terminator->start();
        const KerberosExchange::Step step = exchange->accept(token, {});
        if (step.error.empty() && step.complete) {
          ++accepted;
        } else {
          ++refused;
          ADD_FAILURE() << "refused: " << step.error;
        }
      }
    });
  }
  for (std::thread& w : workers) {
    w.join();
  }
  stop = true;
  rotator.join();
  EXPECT_EQ(refused, 0);
  EXPECT_EQ(accepted, kThreads * kRounds);
}

TEST_F(Terminate, TicketForAnotherServiceIsRefused) {
  Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = settings(false)});
  Client alice(dir_, kServerSpn, GSS_C_MUTUAL_FLAG); // Aimed past the proxy.
  Server server(dir_);
  auto error = login(h, alice, server);
  ASSERT_TRUE(error);
  EXPECT_EQ(error->kind, BridgeError::Kind::Denied);
  EXPECT_NE(error->message.find("Kerberos login to the proxy failed"), std::string::npos)
      << error->message;
}

TEST_F(Terminate, ReplayedLoginIsRefused) {
  auto auth = settings(false);
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG);
  Login7Fields f;
  f.user = "";
  f.integrated = true;
  f.sspi = alice.step();
  for (int attempt = 0; attempt < 2; ++attempt) {
    Harness h(kEncOn, kEncOn, 0, false, contexts(), BridgeOptions{.auth = auth});
    ASSERT_TRUE(h.connect()) << h.message();
    h.client.send(kTdsLogin7, login7Payload(f), true);
    const bool ok = h.pump();
    if (attempt == 0) {
      EXPECT_TRUE(ok) << h.message();
    } else {
      ASSERT_FALSE(ok) << "the proxy keeps a replay cache";
      EXPECT_NE(h.message().find("replay"), std::string::npos) << h.message();
    }
  }
}

TEST_F(Terminate, ChannelBindingOnBothLegs) {
  // The server checks the proxy's binding to its certificate; a client that
  // binds to the proxy's is checked, and one that doesn't bind still logs in.
  for (bool client_binds : {true, false}) {
    Harness h(kEncOn, kEncOn, 0, false, contexts(),
              BridgeOptions{.auth = settings(false, ChannelBinding::TlsServerEndPoint)});
    Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG,
                 client_binds ? endPoint(proxyCert().cert_pem) : "");
    Server server(dir_);
    ASSERT_FALSE(login(h, alice, server, endPoint(serverCert().cert_pem))) << h.message();
    EXPECT_EQ(alice.status, GSS_S_COMPLETE);
  }
}

TEST_F(Terminate, WrongClientBindingIsRefused) {
  Harness h(kEncOn, kEncOn, 0, false, contexts(),
            BridgeOptions{.auth = settings(false, ChannelBinding::TlsServerEndPoint)});
  // Bound to another certificate, as through a man in the middle.
  Client alice(dir_, kProxySpn, GSS_C_MUTUAL_FLAG, endPoint(serverCert().cert_pem));
  Server server(dir_);
  auto error = login(h, alice, server);
  ASSERT_TRUE(error);
  EXPECT_EQ(error->kind, BridgeError::Kind::Denied);
  EXPECT_NE(error->message.find("Kerberos login to the proxy failed"), std::string::npos)
      << error->message;
}

TEST_F(Terminate, CreateChecksItsKeytabs) {
  std::string error;
  EXPECT_FALSE(GssTerminator::create({.keytab_path = dir_ + "/missing.keytab"}, error));
  EXPECT_FALSE(error.empty());
  EXPECT_FALSE(GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab"}, error));
  EXPECT_NE(error.find("client keytab"), std::string::npos) << error;
  EXPECT_FALSE(GssTerminator::create({.keytab_path = dir_ + "/proxy.keytab",
                                      .client_keytab_path = dir_ + "/missing.keytab"},
                                     error));
}

} // namespace
} // namespace MssqlProxy

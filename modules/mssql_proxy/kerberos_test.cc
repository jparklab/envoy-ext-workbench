// Kerberos read_ticket against a throwaway MIT KDC (testdata/mit_kdc.sh): real
// tickets and AP-REQs, read with the service keytab. Skipped when the MIT KDC
// tools are missing.

#include "kerberos.h"

#include <ctime>
#include <string>

#include "auth.h"
#include "gtest/gtest.h"
#include "kdc_test_util.h"
#include "krb5_util.h"
#include "krb5_messages.h"
#include "test_util.h"

namespace MssqlProxy {
namespace {

using namespace test;

constexpr const char* kService = "MSSQLSvc/sql.test:1433@TEST.REALM";
constexpr const char* kOtherService = "MSSQLSvc/other.test:1433@TEST.REALM";

class Kerberos : public ThrowawayKdc {
protected:
  std::shared_ptr<const KeytabTicketReader> reader() {
    std::string error;
    auto r = KeytabTicketReader::create(dir_ + "/service.keytab", error);
    EXPECT_TRUE(r) << error;
    return r;
  }

  // alice's AP-REQ for service, as a client sends it inside GSS framing.
  static std::string apReq(const char* service) {
    krb5_context ctx = nullptr;
    EXPECT_EQ(krb5_init_context(&ctx), 0);
    krb5_ccache cc = nullptr;
    EXPECT_EQ(krb5_cc_resolve(ctx, ("FILE:" + dir_ + "/alice.ccache").c_str(), &cc), 0);
    krb5_creds in{};
    EXPECT_EQ(krb5_cc_get_principal(ctx, cc, &in.client), 0);
    EXPECT_EQ(krb5_parse_name(ctx, service, &in.server), 0);
    krb5_creds* creds = nullptr;
    krb5_error_code code = krb5_get_credentials(ctx, 0, cc, &in, &creds);
    EXPECT_EQ(code, 0) << krb5Message(ctx, code);
    std::string out;
    if (code == 0) {
      krb5_auth_context ac = nullptr;
      krb5_auth_con_init(ctx, &ac);
      krb5_data req{};
      code = krb5_mk_req_extended(ctx, &ac, AP_OPTS_MUTUAL_REQUIRED, nullptr, creds, &req);
      EXPECT_EQ(code, 0) << krb5Message(ctx, code);
      out.assign(req.data, req.length);
      krb5_free_data_contents(ctx, &req);
      krb5_auth_con_free(ctx, ac);
      krb5_free_creds(ctx, creds);
    }
    krb5_free_principal(ctx, in.client);
    krb5_free_principal(ctx, in.server);
    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return out;
  }

  static int64_t now() { return static_cast<int64_t>(std::time(nullptr)); }
};

TEST_F(Kerberos, ReadsTheClientPrincipal) {
  const std::string req = apReq(kService);
  std::string error;
  auto info = reader()->read(req, now(), error);
  ASSERT_TRUE(info) << error;
  EXPECT_EQ(info->client, "alice@TEST.REALM");
  EXPECT_EQ(info->service, kService);
  EXPECT_GT(info->endtime, now());
}

TEST_F(Kerberos, KeepsNoReplayCache) {
  // The same AP-REQ reads twice: nothing was recorded, so the server's own
  // replay check is the only one that sees it.
  const std::string req = apReq(kService);
  std::string error;
  auto r = reader();
  ASSERT_TRUE(r->read(req, now(), error)) << error;
  ASSERT_TRUE(r->read(req, now(), error)) << error;
}

TEST_F(Kerberos, RefusesATicketForAnotherService) {
  std::string error;
  EXPECT_FALSE(reader()->read(apReq(kOtherService), now(), error));
  EXPECT_NE(error.find("other.test"), std::string::npos) << error;
}

TEST_F(Kerberos, RefusesAnExpiredTicket) {
  std::string error;
  EXPECT_FALSE(reader()->read(apReq(kService), now() + 2 * 3600, error));
  EXPECT_NE(error.find("expired"), std::string::npos) << error;
  EXPECT_FALSE(reader()->read(apReq(kService), now() - 3600, error));
  EXPECT_NE(error.find("not yet valid"), std::string::npos) << error;
}

TEST_F(Kerberos, RefusesATamperedAuthenticator) {
  std::string req = apReq(kService);
  req.back() ^= 0x01; // The authenticator's ciphertext ends the AP-REQ.
  std::string error;
  EXPECT_FALSE(reader()->read(req, now(), error));
  EXPECT_NE(error.find("authenticator"), std::string::npos) << error;
}

TEST_F(Kerberos, RefusesMalformedAndTruncatedApReq) {
  const std::string req = apReq(kService);
  std::string error;
  for (const std::string& bad : {std::string("garbage"), req.substr(0, req.size() / 2)}) {
    EXPECT_FALSE(reader()->read(bad, now(), error));
    EXPECT_NE(error.find("AP-REQ"), std::string::npos) << error;
  }
  auto parsed = parseApReq(req, error);
  ASSERT_TRUE(parsed) << error;
  EXPECT_EQ(principalString(parsed->ticket_sname, parsed->ticket_realm), kService);
  EXPECT_TRUE(parsed->ap_options & 0x20000000) << "mutual-required";
}

TEST_F(Kerberos, KeytabChecks) {
  std::string error;
  EXPECT_FALSE(KeytabTicketReader::create(dir_ + "/missing.keytab", error));
  EXPECT_FALSE(error.empty());
}

// The whole path: a SPNEGO-wrapped AP-REQ in LOGIN7, through the policy.
TEST_F(Kerberos, LoginIdentityAndPolicy) {
  auto settings = std::make_shared<AuthSettings>();
  settings->kerberos = reader();
  Login7 login;
  login.integrated = true;
  login.has_sspi = true;
  login.sspi = spnegoInit({kOidMsKrb5, kOidKrb5, kOidNtlm}, krb5Token(0x0100, apReq(kService)));

  LoginAuth auth(settings);
  EXPECT_FALSE(auth.onLogin7(login));
  EXPECT_EQ(auth.method(), LoginMethod::Kerberos);
  EXPECT_EQ(auth.identity(), "alice@TEST.REALM");
  EXPECT_EQ(auth.kerberosPrincipal(), "alice@TEST.REALM");

  settings->deny = {"ALICE@test.realm"};
  LoginAuth denied(settings);
  EXPECT_TRUE(denied.onLogin7(login));

  settings->deny.clear();
  login.sspi = spnegoInit({kOidKrb5}, krb5Token(0x0100, apReq(kOtherService)));
  LoginAuth unreadable(settings);
  auto denial = unreadable.onLogin7(login);
  ASSERT_TRUE(denial) << "a ticket the keytab can't read is refused";
  EXPECT_NE(denial->reason.find("Kerberos ticket not accepted"), std::string::npos);
}

} // namespace
} // namespace MssqlProxy

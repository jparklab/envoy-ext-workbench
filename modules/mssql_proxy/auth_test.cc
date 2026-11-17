#include "auth.h"

#include <string>

#include "gss_token.h"
#include "gtest/gtest.h"
#include "test_util.h"

namespace MssqlProxy {
namespace {

using namespace test;

std::optional<AuthToken> parse(std::string_view token) {
  std::string error;
  auto t = parseAuthToken(token, error);
  EXPECT_TRUE(t) << error;
  return t;
}

// ---------------------------------------------------------------- tokens

TEST(AuthToken, RawNtlm) {
  const std::string msg = ntlmMessage(1);
  auto t = parse(msg);
  ASSERT_TRUE(t);
  EXPECT_EQ(t->mechanism, AuthMechanism::Ntlm);
  EXPECT_FALSE(t->spnego);
  EXPECT_EQ(t->inner, msg);
}

TEST(AuthToken, BareKerberos) {
  const std::string token = krb5Token(0x0100, "the-ap-req");
  auto t = parse(token);
  ASSERT_TRUE(t);
  EXPECT_EQ(t->mechanism, AuthMechanism::Kerberos);
  EXPECT_FALSE(t->spnego);
  EXPECT_EQ(t->krb5_tok_id, 0x0100);
  EXPECT_EQ(t->inner, "the-ap-req");
}

TEST(AuthToken, SpnegoInitWithKerberos) {
  // As Windows sends it: MS Kerberos, Kerberos, NTLM, optimistic Kerberos token.
  const std::string token =
      spnegoInit({kOidMsKrb5, kOidKrb5, kOidNtlm}, krb5Token(0x0100, std::string(300, 'k')));
  auto t = parse(token);
  ASSERT_TRUE(t);
  EXPECT_TRUE(t->spnego);
  EXPECT_EQ(t->mechanism, AuthMechanism::Kerberos);
  EXPECT_EQ(t->offered, (std::vector<AuthMechanism>{AuthMechanism::Kerberos,
                                                     AuthMechanism::Kerberos,
                                                     AuthMechanism::Ntlm}));
  EXPECT_EQ(t->inner, std::string(300, 'k')) << "long-form DER lengths";
}

TEST(AuthToken, SpnegoInitWithNtlm) {
  const std::string token = spnegoInit({kOidNtlm}, ntlmMessage(1));
  auto t = parse(token); // Views token.
  ASSERT_TRUE(t);
  EXPECT_EQ(t->mechanism, AuthMechanism::Ntlm);
  EXPECT_EQ(t->inner, ntlmMessage(1));
}

TEST(AuthToken, SpnegoInitWithoutTokenTakesFirstOffer) {
  const std::string token = spnegoInit({kOidNtlm, kOidKrb5}, std::nullopt);
  auto t = parse(token);
  ASSERT_TRUE(t);
  EXPECT_EQ(t->mechanism, AuthMechanism::Ntlm);
  EXPECT_TRUE(t->inner.empty());
}

TEST(AuthToken, SpnegoRespWithNtlmAuthenticate) {
  const std::string token = spnegoResp(ntlmMessage(3));
  auto t = parse(token);
  ASSERT_TRUE(t);
  EXPECT_TRUE(t->spnego);
  EXPECT_EQ(t->mechanism, AuthMechanism::Ntlm);
  EXPECT_EQ(t->inner, ntlmMessage(3));
}

TEST(AuthToken, RejectsMalformed) {
  const std::string init = spnegoInit({kOidKrb5}, krb5Token());
  const std::string cases[] = {
      "",
      "garbage",
      init.substr(0, init.size() - 1),                // Truncated.
      init + "x",                                     // Trailing data.
      std::string("\x60\x80\x00\x00", 4),             // Indefinite length.
      std::string("\x60\x85\x01\x00\x00\x00\x00", 7), // Length of 5 bytes.
      der(0x60, der(0x06, "\x2a\x03") + "inner"),     // Unknown GSS mechanism.
      der(0x60, der(0x06, kOidKrb5) + "\x01"),        // No TOK_ID.
      spnegoInit({}, krb5Token()),                    // Nothing offered.
      der(0x60, der(0x06, kOidSpnego) + der(0xa0, der(0x31, ""))), // Not a SEQUENCE.
  };
  for (const std::string& token : cases) {
    std::string error;
    EXPECT_FALSE(parseAuthToken(token, error)) << testing::PrintToString(token);
    EXPECT_FALSE(error.empty());
  }
}

// ---------------------------------------------------------------- login

Login7 sqlLogin(std::string user) {
  Login7 l;
  l.user_name = std::move(user);
  return l;
}

Login7 integratedLogin(std::string sspi) {
  Login7 l;
  l.integrated = true;
  l.has_sspi = !sspi.empty();
  l.sspi = std::move(sspi);
  return l;
}

std::shared_ptr<const AuthSettings> settings(bool ntlm_allowed, std::vector<std::string> deny) {
  return std::make_shared<const AuthSettings>(AuthSettings{ntlm_allowed, std::move(deny)});
}

TEST(LoginAuth, SqlLoginAndResult) {
  LoginAuth auth(nullptr);
  EXPECT_FALSE(auth.onLogin7(sqlLogin("app_user")));
  EXPECT_EQ(auth.method(), LoginMethod::Sql);
  EXPECT_EQ(auth.identity(), "app_user");
  EXPECT_EQ(auth.result(), LoginResult::Pending);

  LoginResponseScan scan;
  scan.login_ack = true;
  auth.onServerLoginMessage(scan);
  EXPECT_EQ(auth.result(), LoginResult::Succeeded);
}

TEST(LoginAuth, ServerRefusal) {
  LoginAuth auth(nullptr);
  auth.onLogin7(sqlLogin("app_user"));
  LoginResponseScan scan;
  scan.error = 18456;
  auth.onServerLoginMessage(scan);
  EXPECT_EQ(auth.result(), LoginResult::Failed);
  EXPECT_EQ(auth.serverError(), 18456u);
}

TEST(LoginAuth, SspiRoundKeepsPending) {
  LoginAuth auth(nullptr);
  auth.onLogin7(integratedLogin(spnegoInit({kOidNtlm}, ntlmMessage(1))));
  LoginResponseScan challenge;
  challenge.sspi = "challenge";
  auth.onServerLoginMessage(challenge);
  EXPECT_EQ(auth.result(), LoginResult::Pending);
}

TEST(LoginAuth, DenyList) {
  LoginAuth auth(settings(true, {"SA", "other"}));
  auto denial = auth.onLogin7(sqlLogin("sa"));
  ASSERT_TRUE(denial) << "matched ignoring case";
  EXPECT_EQ(denial->client_text, "Login failed for user 'sa'.");

  LoginAuth allowed(settings(true, {"sa"}));
  EXPECT_FALSE(allowed.onLogin7(sqlLogin("sam")));
}

TEST(LoginAuth, IntegratedMechanisms) {
  LoginAuth kerberos(nullptr);
  EXPECT_FALSE(kerberos.onLogin7(integratedLogin(spnegoInit({kOidKrb5}, krb5Token()))));
  EXPECT_EQ(kerberos.method(), LoginMethod::Kerberos);
  EXPECT_EQ(kerberos.identity(), "");

  LoginAuth ntlm(nullptr);
  EXPECT_FALSE(ntlm.onLogin7(integratedLogin(ntlmMessage(1))));
  EXPECT_EQ(ntlm.method(), LoginMethod::Ntlm);

  LoginAuth unknown(nullptr);
  EXPECT_FALSE(unknown.onLogin7(integratedLogin("garbage")));
  EXPECT_EQ(unknown.method(), LoginMethod::Integrated);
}

TEST(LoginAuth, NtlmDenied) {
  LoginAuth auth(settings(false, {}));
  EXPECT_TRUE(auth.onLogin7(integratedLogin(spnegoInit({kOidNtlm}, ntlmMessage(1)))));
}

TEST(LoginAuth, NtlmDeniedFailsClosedOnUnknownMechanism) {
  LoginAuth garbage(settings(false, {}));
  EXPECT_TRUE(garbage.onLogin7(integratedLogin("garbage")));
  LoginAuth no_token(settings(false, {}));
  EXPECT_TRUE(no_token.onLogin7(integratedLogin("")));
}

TEST(LoginAuth, NtlmDeniedAfterKerberosFallsBack) {
  // SPNEGO starts with Kerberos; the client then switches to NTLM.
  LoginAuth auth(settings(false, {}));
  EXPECT_FALSE(auth.onLogin7(integratedLogin(spnegoInit({kOidKrb5, kOidNtlm}, krb5Token()))));
  EXPECT_EQ(auth.method(), LoginMethod::Kerberos);
  EXPECT_TRUE(auth.onClientSspi(spnegoResp(ntlmMessage(3))));
  EXPECT_EQ(auth.method(), LoginMethod::Ntlm);
}

TEST(LoginAuth, SqlLoginIgnoresSspiPackets) {
  LoginAuth auth(settings(false, {}));
  EXPECT_FALSE(auth.onLogin7(sqlLogin("app_user")));
  EXPECT_FALSE(auth.onClientSspi(ntlmMessage(3)));
  EXPECT_EQ(auth.method(), LoginMethod::Sql);
}

TEST(LoginAuth, Federated) {
  Login7 l;
  l.has_extension = true;
  LoginAuth auth(nullptr);
  EXPECT_FALSE(auth.onLogin7(l));
  EXPECT_EQ(auth.method(), LoginMethod::Federated);
}

} // namespace
} // namespace MssqlProxy

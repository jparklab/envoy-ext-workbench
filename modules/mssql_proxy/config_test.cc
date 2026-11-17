#include "config.h"

#include <format>
#include <map>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace MssqlProxy {
namespace {

// Files served from memory.
FileReader files(std::map<std::string, std::string> contents) {
  return [contents](const std::string& path, std::string& error) -> std::optional<std::string> {
    auto it = contents.find(path);
    if (it == contents.end()) {
      error = "no such file " + path;
      return std::nullopt;
    }
    return it->second;
  };
}

const FileReader kFiles = files({{"/c.pem", "CERT"}, {"/k.pem", "KEY"}, {"/ca.pem", "CA"}});

TEST(Config, EmptyMeansObserveOnly) {
  std::string error;
  for (std::string_view json : {"", "  ", "{}"}) {
    auto config = parseFilterConfig(json, kFiles, error);
    ASSERT_TRUE(config) << error;
    EXPECT_FALSE(config->tls);
  }
}

TEST(Config, Tls) {
  std::string error;
  auto config = parseFilterConfig(R"({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem",
      "upstream_ca_file": "/ca.pem", "upstream_server_name": "sql.test"}})",
                                  kFiles, error);
  ASSERT_TRUE(config) << error;
  ASSERT_TRUE(config->tls);
  EXPECT_EQ(config->tls->cert_pem, "CERT");
  EXPECT_EQ(config->tls->key_pem, "KEY");
  EXPECT_EQ(config->tls->upstream_ca_pem, "CA");
  EXPECT_EQ(config->tls->upstream_server_name, "sql.test");
  EXPECT_TRUE(config->tls->upstream_verify);
}

TEST(Config, VerifyOffNeedsNoCa) {
  std::string error;
  auto config = parseFilterConfig(
      R"({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem", "upstream_verify": false}})", kFiles,
      error);
  ASSERT_TRUE(config) << error;
  EXPECT_FALSE(config->tls->upstream_verify);
}

TEST(Config, Rejects) {
  const std::map<std::string, std::string> cases = {
      {"[]", "JSON object"},
      {"{nope", "JSON object"},
      {R"({"tsl": {}})", "unknown key \"tsl\""},
      {R"({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem", "upstream_ca_file": "/ca.pem",
          "verify": false}})",
       "unknown key \"verify\""},
      {R"({"tls": {"key_file": "/k.pem", "upstream_ca_file": "/ca.pem"}})", "cert_file is required"},
      {R"({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem"}})",
       "upstream_ca_file is required"},
      {R"({"tls": {"cert_file": "/missing", "key_file": "/k.pem", "upstream_ca_file": "/ca.pem"}})",
       "no such file /missing"},
      {R"({"tls": {"cert_file": 1, "key_file": "/k.pem", "upstream_ca_file": "/ca.pem"}})",
       "non-empty string"},
      {R"({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem", "upstream_verify": "no"}})",
       "true or false"},
      {R"({"tls": "on"})", "must be an object"},
  };
  for (const auto& [json, want] : cases) {
    std::string error;
    EXPECT_FALSE(parseFilterConfig(json, kFiles, error)) << json;
    EXPECT_NE(error.find(want), std::string::npos) << json << " -> " << error;
  }
}

constexpr std::string_view kTls =
    R"("tls": {"cert_file": "/c.pem", "key_file": "/k.pem", "upstream_ca_file": "/ca.pem"})";

TEST(Config, Routing) {
  std::string error;
  auto config = parseFilterConfig(std::format(R"({{{}, "routing": {{"routes": [
      {{"match": {{"database": "Sales", "user": "etl"}}, "cluster": "batch"}},
      {{"match": {{"database": "sales"}}, "cluster": "sales"}},
      {{"cluster": "catch_all"}}]}}}})",
                                              kTls),
                                  kFiles, error);
  ASSERT_TRUE(config) << error;
  ASSERT_TRUE(config->routing);
  ASSERT_EQ(config->routing->routes.size(), 3u);

  Login7 login;
  login.database = "SALES";
  login.user_name = "etl";
  EXPECT_EQ(selectRoute(*config->routing, login)->cluster, "batch") << "all fields, any case";
  login.user_name = "other";
  EXPECT_EQ(selectRoute(*config->routing, login)->cluster, "sales") << "first match wins";
  login.database = "hr";
  EXPECT_EQ(selectRoute(*config->routing, login)->cluster, "catch_all") << "empty match";

  config->routing->routes.pop_back();
  EXPECT_EQ(selectRoute(*config->routing, login), nullptr);
}

TEST(Config, RejectsBadRouting) {
  const std::map<std::string, std::string> cases = {
      {R"({"routing": {"routes": []}})", "routing needs tls"},
      {std::format(R"({{{}, "routing": []}})", kTls), "routing must be an object"},
      {std::format(R"({{{}, "routing": {{"routes": {{}}}}}})", kTls), "must be a list"},
      {std::format(R"({{{}, "routing": {{"routes": [{{"match": {{}}}}]}}}})", kTls),
       "cluster is required"},
      {std::format(R"({{{}, "routing": {{"routes": [{{"match": {{"db": "x"}}, "cluster": "c"}}]}}}})",
                   kTls),
       "unknown key \"db\""},
      {std::format(R"({{{}, "routing": {{"routes": [{{"match": {{"user": 1}}, "cluster": "c"}}]}}}})",
                   kTls),
       "must be a string"},
  };
  for (const auto& [json, want] : cases) {
    std::string error;
    EXPECT_FALSE(parseFilterConfig(json, kFiles, error)) << json;
    EXPECT_NE(error.find(want), std::string::npos) << json << " -> " << error;
  }
}

TEST(Config, Auth) {
  std::string error;
  auto config = parseFilterConfig(
      std::format(R"({{{}, "auth": {{"ntlm": "deny", "deny": ["sa", "CORP\\old"]}}}})", kTls),
      kFiles, error);
  ASSERT_TRUE(config) << error;
  ASSERT_TRUE(config->auth);
  EXPECT_FALSE(config->auth->ntlm_allowed);
  EXPECT_EQ(config->auth->deny, (std::vector<std::string>{"sa", "CORP\\old"}));

  config = parseFilterConfig(std::format(R"({{{}, "auth": {{}}}})", kTls), kFiles, error);
  ASSERT_TRUE(config) << error;
  EXPECT_TRUE(config->auth->ntlm_allowed) << "NTLM passes through by default";
  EXPECT_TRUE(config->auth->ntlm_v1_allowed);

  config = parseFilterConfig(std::format(R"({{{}, "auth": {{"ntlm": "v2_only"}}}})", kTls),
                             kFiles, error);
  ASSERT_TRUE(config) << error;
  EXPECT_TRUE(config->auth->ntlm_allowed);
  EXPECT_FALSE(config->auth->ntlm_v1_allowed);
}

TEST(Config, Kerberos) {
  const FileReader files_with_keytab =
      files({{"/c.pem", "CERT"}, {"/k.pem", "KEY"}, {"/ca.pem", "CA"}, {"/svc.keytab", "KT"}});
  std::string error;
  auto config = parseFilterConfig(std::format(R"({{{}, "auth": {{"kerberos": {{
      "mode": "read_ticket", "keytab_file": "/svc.keytab"}}}},
      "routing": {{"routes": [{{"match": {{"principal": "alice@TEST.REALM"}}, "cluster": "a"}}]}}}})",
                                              kTls),
                                  files_with_keytab, error);
  ASSERT_TRUE(config) << error;
  ASSERT_TRUE(config->kerberos);
  EXPECT_EQ(config->kerberos->keytab_path, "/svc.keytab");

  Login7 login;
  EXPECT_EQ(selectRoute(*config->routing, login, "ALICE@test.realm")->cluster, "a");
  EXPECT_EQ(selectRoute(*config->routing, login, ""), nullptr) << "no principal: no match";
}

TEST(Config, RejectsBadAuth) {
  const std::map<std::string, std::string> cases = {
      {R"({"auth": {}})", "auth needs tls"},
      {std::format(R"({{{}, "auth": []}})", kTls), "auth must be an object"},
      {std::format(R"({{{}, "auth": {{"kerberos": {{}}}}}})", kTls), "mode is required"},
      {std::format(R"({{{}, "auth": {{"kerberos": {{"mode": "terminate"}}}}}})", kTls),
       "must be \"read_ticket\""},
      {std::format(R"({{{}, "auth": {{"kerberos": {{"mode": "read_ticket"}}}}}})", kTls),
       "keytab_file is required"},
      {std::format(R"({{{}, "auth": {{"kerberos": {{"mode": "read_ticket",
          "keytab_file": "/missing"}}}}}})", kTls),
       "no such file /missing"},
      {std::format(R"({{{}, "auth": {{"kerberos": {{"mode": "read_ticket", "keytab": "/k"}}}}}})",
                   kTls),
       "unknown key \"keytab\""},
      {std::format(R"({{{}, "auth": {{"ntlm": "relay"}}}})", kTls), "pass_through"},
      {std::format(R"({{{}, "auth": {{"deny": "sa"}}}})", kTls), "must be a list"},
      {std::format(R"({{{}, "auth": {{"deny": [""]}}}})", kTls), "non-empty strings"},
  };
  for (const auto& [json, want] : cases) {
    std::string error;
    EXPECT_FALSE(parseFilterConfig(json, kFiles, error)) << json;
    EXPECT_NE(error.find(want), std::string::npos) << json << " -> " << error;
  }
}

} // namespace
} // namespace MssqlProxy

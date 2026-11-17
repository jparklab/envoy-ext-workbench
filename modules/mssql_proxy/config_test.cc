#include "config.h"

#include <map>
#include <string>

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

} // namespace
} // namespace MssqlProxy

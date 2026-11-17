#pragma once

// Test-only: a gtest fixture that starts the throwaway MIT KDC of
// testdata/mit_kdc.sh (realm TEST.REALM, random keys) once per test suite and
// stops it afterwards. Tests skip when the MIT KDC tools are missing. The test
// target sets MIT_KDC to the script's runfiles path.

#include <signal.h>
#include <sys/wait.h>

#include <cstdlib>
#include <fstream>
#include <string>

#include "gtest/gtest.h"

namespace MssqlProxy {
namespace test {

class ThrowawayKdc : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    const char* tmp = std::getenv("TEST_TMPDIR");
    const char* srcdir = std::getenv("TEST_SRCDIR");
    const char* script = std::getenv("MIT_KDC");
    ASSERT_TRUE(tmp && srcdir && script) << "TEST_TMPDIR, TEST_SRCDIR or MIT_KDC not set";
    dir_ = std::string(tmp) + "/kdc";
    const std::string command =
        std::string("bash ") + srcdir + "/" + script + " " + dir_ + " >" + tmp + "/kdc.out 2>&1";
    const int status = std::system(command.c_str());
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
      skip_ = "MIT KDC tools not installed";
      return;
    }
    ASSERT_EQ(status, 0) << "mit_kdc.sh failed; see " << tmp << "/kdc.out";
    // Before the first Kerberos context of this process. The replay cache
    // goes to the test's own directory.
    setenv("KRB5_CONFIG", (dir_ + "/krb5.conf").c_str(), 1);
    setenv("KRB5RCACHEDIR", tmp, 1);
  }

  static void TearDownTestSuite() {
    std::ifstream pid_file(dir_ + "/kdc.pid");
    pid_t pid = 0;
    if (pid_file >> pid && pid > 0) {
      kill(pid, SIGTERM);
    }
  }

  void SetUp() override {
    if (!skip_.empty()) {
      GTEST_SKIP() << skip_;
    }
  }

  inline static std::string skip_;
  inline static std::string dir_; // The KDC's files (see mit_kdc.sh).
};

} // namespace test
} // namespace MssqlProxy

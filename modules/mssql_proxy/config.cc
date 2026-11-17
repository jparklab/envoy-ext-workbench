#include "config.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <format>
#include <fstream>
#include <set>
#include <sstream>

#include "include/nlohmann/json.hpp"

namespace MssqlProxy {

namespace {

using Json = nlohmann::json;

bool checkKeys(const Json& object, std::string_view where, const std::set<std::string>& allowed,
               std::string& error) {
  for (const auto& [key, value] : object.items()) {
    if (!allowed.contains(key)) {
      error = std::format("{}: unknown key \"{}\"", where, key);
      return false;
    }
  }
  return true;
}

// The string at key, or nullopt when absent (error unset) or not a non-empty
// string (error set).
std::optional<std::string> getString(const Json& object, const std::string& key,
                                     std::string_view where, std::string& error) {
  auto it = object.find(key);
  if (it == object.end()) {
    return std::nullopt;
  }
  if (!it->is_string() || it->get_ref<const std::string&>().empty()) {
    error = std::format("{}.{} must be a non-empty string", where, key);
    return std::nullopt;
  }
  return it->get<std::string>();
}

std::optional<TlsSettings> parseTls(const Json& tls, const FileReader& read_file,
                                    std::string& error) {
  constexpr std::string_view kWhere = "tls";
  if (!tls.is_object()) {
    error = "tls must be an object";
    return std::nullopt;
  }
  if (!checkKeys(tls, kWhere,
                 {"cert_file", "key_file", "upstream_ca_file", "upstream_server_name",
                  "upstream_verify"},
                 error)) {
    return std::nullopt;
  }
  TlsSettings settings;
  if (auto it = tls.find("upstream_verify"); it != tls.end()) {
    if (!it->is_boolean()) {
      error = "tls.upstream_verify must be true or false";
      return std::nullopt;
    }
    settings.upstream_verify = it->get<bool>();
  }

  // Reads the file named at key into `into`; false (error set) on failure.
  auto file = [&](const std::string& key, bool required, std::string& into) {
    std::optional<std::string> path = getString(tls, key, kWhere, error);
    if (!path) {
      if (error.empty() && required) {
        error = std::format("{}.{} is required", kWhere, key);
      }
      return error.empty();
    }
    std::optional<std::string> contents = read_file(*path, error);
    if (!contents) {
      error = std::format("{}.{}: {}", kWhere, key, error);
      return false;
    }
    into = std::move(*contents);
    return true;
  };
  if (!file("cert_file", true, settings.cert_pem) || !file("key_file", true, settings.key_pem) ||
      !file("upstream_ca_file", settings.upstream_verify, settings.upstream_ca_pem)) {
    return std::nullopt;
  }
  if (auto name = getString(tls, "upstream_server_name", kWhere, error)) {
    settings.upstream_server_name = *name;
  } else if (!error.empty()) {
    return std::nullopt;
  }
  return settings;
}

constexpr std::string_view kMatchKeys[] = {"database", "user",        "server_name",
                                           "app_name", "client_host", "library"};

std::optional<RoutingConfig> parseRouting(const Json& routing, std::string& error) {
  if (!routing.is_object()) {
    error = "routing must be an object";
    return std::nullopt;
  }
  if (!checkKeys(routing, "routing", {"routes"}, error)) {
    return std::nullopt;
  }
  RoutingConfig config;
  auto routes = routing.find("routes");
  if (routes == routing.end()) {
    return config;
  }
  if (!routes->is_array()) {
    error = "routing.routes must be a list";
    return std::nullopt;
  }
  for (size_t n = 0; n < routes->size(); ++n) {
    const Json& entry = (*routes)[n];
    const std::string where = std::format("routing.routes[{}]", n);
    if (!entry.is_object()) {
      error = where + " must be an object";
      return std::nullopt;
    }
    if (!checkKeys(entry, where, {"match", "cluster"}, error)) {
      return std::nullopt;
    }
    Route route;
    std::optional<std::string> cluster = getString(entry, "cluster", where, error);
    if (!cluster) {
      if (error.empty()) {
        error = where + ".cluster is required";
      }
      return std::nullopt;
    }
    route.cluster = *cluster;
    if (auto match = entry.find("match"); match != entry.end()) {
      if (!match->is_object()) {
        error = where + ".match must be an object";
        return std::nullopt;
      }
      for (const auto& [key, value] : match->items()) {
        if (std::find(std::begin(kMatchKeys), std::end(kMatchKeys), key) ==
            std::end(kMatchKeys)) {
          error = std::format("{}.match: unknown key \"{}\"", where, key);
          return std::nullopt;
        }
        if (!value.is_string()) {
          error = std::format("{}.match.{} must be a string", where, key);
          return std::nullopt;
        }
        route.match.emplace_back(key, value.get<std::string>());
      }
    }
    config.routes.push_back(std::move(route));
  }
  return config;
}

std::optional<AuthSettings> parseAuth(const Json& auth, std::string& error) {
  if (!auth.is_object()) {
    error = "auth must be an object";
    return std::nullopt;
  }
  if (!checkKeys(auth, "auth", {"ntlm", "deny"}, error)) {
    return std::nullopt;
  }
  AuthSettings settings;
  if (auto ntlm = getString(auth, "ntlm", "auth", error)) {
    if (*ntlm == "deny") {
      settings.ntlm_allowed = false;
    } else if (*ntlm != "pass_through") {
      error = "auth.ntlm must be \"pass_through\" or \"deny\"";
      return std::nullopt;
    }
  } else if (!error.empty()) {
    return std::nullopt;
  }
  if (auto deny = auth.find("deny"); deny != auth.end()) {
    if (!deny->is_array()) {
      error = "auth.deny must be a list";
      return std::nullopt;
    }
    for (const Json& name : *deny) {
      if (!name.is_string() || name.get_ref<const std::string&>().empty()) {
        error = "auth.deny entries must be non-empty strings";
        return std::nullopt;
      }
      settings.deny.push_back(name.get<std::string>());
    }
  }
  return settings;
}

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
  return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char x, char y) {
    return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
  });
}

const std::string& loginField(const Login7& login, std::string_view key) {
  if (key == "database") {
    return login.database;
  }
  if (key == "user") {
    return login.user_name;
  }
  if (key == "server_name") {
    return login.server_name;
  }
  if (key == "app_name") {
    return login.app_name;
  }
  if (key == "client_host") {
    return login.host_name;
  }
  return login.library_name; // "library"; keys are checked at config load.
}

} // namespace

const Route* selectRoute(const RoutingConfig& routing, const Login7& login) {
  for (const Route& route : routing.routes) {
    const bool matches = std::all_of(route.match.begin(), route.match.end(), [&](const auto& m) {
      return equalsIgnoreCase(loginField(login, m.first), m.second);
    });
    if (matches) {
      return &route;
    }
  }
  return nullptr;
}

std::optional<std::string> readFile(const std::string& path, std::string& error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    error = std::format("cannot open {}: {}", path, std::strerror(errno));
    return std::nullopt;
  }
  std::ostringstream contents;
  contents << in.rdbuf();
  if (in.bad()) {
    error = std::format("cannot read {}", path);
    return std::nullopt;
  }
  return contents.str();
}

std::optional<FilterConfig> parseFilterConfig(std::string_view json, const FileReader& read_file,
                                              std::string& error) {
  error.clear();
  FilterConfig config;
  if (json.find_first_not_of(" \t\r\n") == std::string_view::npos) {
    return config;
  }
  const Json root = Json::parse(json, nullptr, /*allow_exceptions=*/false);
  if (root.is_discarded() || !root.is_object()) {
    error = "filter_config must be a JSON object";
    return std::nullopt;
  }
  if (!checkKeys(root, "filter_config", {"tls", "routing", "auth"}, error)) {
    return std::nullopt;
  }
  if (auto it = root.find("tls"); it != root.end()) {
    config.tls = parseTls(*it, read_file, error);
    if (!config.tls) {
      return std::nullopt;
    }
  }
  if (auto it = root.find("routing"); it != root.end()) {
    if (!config.tls) {
      // The proxy answers PRELOGIN itself, so it must be able to do the TLS
      // handshake a client asks for.
      error = "routing needs tls";
      return std::nullopt;
    }
    config.routing = parseRouting(*it, error);
    if (!config.routing) {
      return std::nullopt;
    }
  }
  if (auto it = root.find("auth"); it != root.end()) {
    if (!config.tls) {
      // Logins are only readable once TLS is terminated.
      error = "auth needs tls";
      return std::nullopt;
    }
    config.auth = parseAuth(*it, error);
    if (!config.auth) {
      return std::nullopt;
    }
  }
  return config;
}

} // namespace MssqlProxy

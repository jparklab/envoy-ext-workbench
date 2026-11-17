// mssql_proxy: MS SQL Server (TDS) proxy as a dynamic-module network filter.
//
// Network filter "mssql_proxy", placed in front of envoy.filters.network.tcp_proxy
// on the TDS 7.x filter chain (TDS 8.0 strict clients take a separate chain).
// Configured through filter_config (see config.h):
// - without "tls", it follows each connection's TDS framing and encryption
//   mode without changing any bytes (ConnectionTracker);
// - with "tls", it terminates TLS toward the client and opens its own toward
//   the server, so every message passes through in plain text (TlsBridge);
// - with "routing" as well, it answers PRELOGIN itself and holds everything
//   back from tcp_proxy until it has read LOGIN7, then sets the
//   envoy.tcp_proxy.cluster filter state from the first matching route, so
//   tcp_proxy (in ON_DOWNSTREAM_DATA mode with delayed route selection)
//   connects to that cluster.
// LOGIN7 fields go into dynamic metadata under "mssql_proxy" (see
// setLoginMetadata), for access logs. Connections whose framing is malformed
// or breaks the protocol are closed. Authentication comes in a later phase
// (see plan.md).

#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "config.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk_network.h"
#include "tds_connection.h"
#include "tls_bridge.h"

namespace Envoy {
namespace DynamicModules {
namespace {

using MssqlProxy::BridgeError;
using MssqlProxy::BridgeOptions;
using MssqlProxy::BridgeOutput;
using MssqlProxy::Login7;
using MssqlProxy::RoutingConfig;
using MssqlProxy::ConnectionTracker;
using MssqlProxy::EncryptionMode;
using MssqlProxy::TlsBridge;
using MssqlProxy::TlsContexts;

struct Metrics {
  MetricID connections = 0;
  MetricID downstream_rx_bytes = 0; // client -> server
  MetricID upstream_rx_bytes = 0;   // server -> client
  MetricID protocol_errors = 0;
  MetricID tls_errors = 0;
  MetricID unparsed_connections = 0; // Not TDS 7.x: passed through untouched.
  MetricID encryption_none = 0;
  MetricID encryption_login_only = 0;
  MetricID encryption_full = 0;
  MetricID mars_connections = 0;
  MetricID tls_terminated = 0;      // Both TLS handshakes done.
  MetricID login7_seen = 0;         // LOGIN7 messages read in plain text.
  MetricID client_cert_cleared = 0; // Certificate logins turned into normal ones.
  MetricID routed = 0;              // Logins sent to a route's cluster.
  MetricID unrouted = 0;            // Logins no route matched: tcp_proxy's cluster.
  MetricID server_incompatible = 0; // Server's PRELOGIN contradicted the local answer.
};

// Settings shared by every connection of one filter config.
struct Shared {
  Metrics metrics;
  std::shared_ptr<const TlsContexts> tls; // Null when TLS isn't terminated.
  std::optional<RoutingConfig> routing;   // Set when routing on LOGIN7.
};

constexpr std::string_view kMetadataNamespace = "mssql_proxy";

class MssqlProxyFilter : public NetworkFilter {
public:
  MssqlProxyFilter(NetworkFilterHandle& handle, const Shared& shared)
      : handle_(handle), shared_(shared), metrics_(shared.metrics) {
    if (shared.tls) {
      bridge_ = std::make_unique<TlsBridge>(
          shared.tls, BridgeOptions{.answer_prelogin = shared.routing.has_value()});
    } else {
      tracker_ = std::make_unique<ConnectionTracker>();
    }
  }

  NetworkFilterStatus onNewConnection() override {
    handle_.incrementCounterValue(metrics_.connections, 1);
    return NetworkFilterStatus::Continue;
  }

  NetworkFilterStatus onRead(NetworkBuffer& data, bool) override {
    handle_.incrementCounterValue(metrics_.downstream_rx_bytes, data.getSize());
    return bridge_ ? bridge(data, /*client=*/true) : track(data, /*client=*/true);
  }

  NetworkFilterStatus onWrite(NetworkBuffer& data, bool) override {
    handle_.incrementCounterValue(metrics_.upstream_rx_bytes, data.getSize());
    return bridge_ ? bridge(data, /*client=*/false) : track(data, /*client=*/false);
  }

  void onEvent(NetworkConnectionEvent) override {}
  void onDestroy() override {}

private:
  // Observe-only: the bytes pass unchanged.
  NetworkFilterStatus track(NetworkBuffer& data, bool client) {
    if (closed_) {
      return NetworkFilterStatus::Stop;
    }
    const bool was_parsing = tracker_->parsing();
    for (const BufferView& chunk : data.getChunks()) {
      auto error = client ? tracker_->onClientData(chunk.toStringView())
                          : tracker_->onServerData(chunk.toStringView());
      if (error) {
        close(metrics_.protocol_errors, "mssql_proxy_protocol_error", *error);
        return NetworkFilterStatus::Stop;
      }
    }
    report(was_parsing, tracker_->parsing(), tracker_->encryptionMode(), tracker_->marsEnabled());
    return NetworkFilterStatus::Continue;
  }

  // Terminating: the bytes are replaced by what the bridge sends on. Output
  // for this direction rides in the buffer; output for the other direction is
  // injected after this filter (toward the server: tcp_proxy; toward the
  // client: the connection).
  NetworkFilterStatus bridge(NetworkBuffer& data, bool client) {
    if (closed_) {
      data.drain(data.getSize());
      return NetworkFilterStatus::Stop;
    }
    const bool was_parsing = bridge_->parsing();
    BridgeOutput out;
    for (const BufferView& chunk : data.getChunks()) {
      std::optional<BridgeError> error = client ? bridge_->onClientData(chunk.toStringView(), out)
                                                : bridge_->onServerData(chunk.toStringView(), out);
      if (error) {
        closeOnError(*error);
        data.drain(data.getSize());
        return NetworkFilterStatus::Stop;
      }
    }
    data.drain(data.getSize());
    if (!login_reported_ && bridge_->login()) {
      login_reported_ = true;
      handle_.incrementCounterValue(metrics_.login7_seen, 1);
      setLoginMetadata(*bridge_->login());
      if (shared_.routing && !route(*bridge_->login())) {
        return NetworkFilterStatus::Stop;
      }
    }
    if (shared_.routing && bridge_->parsing() && !bridge_->upstreamStarted()) {
      // Nothing may reach tcp_proxy before routing: its first data, even
      // empty, makes it pick the cluster and connect.
      if (!out.to_client.empty()) {
        handle_.injectWriteData(out.to_client, false);
      }
      reportBridge(was_parsing);
      return NetworkFilterStatus::Stop;
    }
    if (client) {
      data.append(out.to_server);
      if (!out.to_client.empty()) {
        handle_.injectWriteData(out.to_client, false);
      }
    } else {
      data.append(out.to_client);
      if (!out.to_server.empty()) {
        handle_.injectReadData(out.to_server, false);
      }
    }

    reportBridge(was_parsing);
    return NetworkFilterStatus::Continue;
  }

  void reportBridge(bool was_parsing) {
    report(was_parsing, bridge_->parsing(), bridge_->encryptionMode(), bridge_->marsEnabled());
    if (!tls_reported_ && bridge_->tlsEstablished()) {
      tls_reported_ = true;
      handle_.incrementCounterValue(metrics_.tls_terminated, 1);
    }
    if (!client_cert_reported_ && bridge_->clientCertCleared()) {
      client_cert_reported_ = true;
      handle_.incrementCounterValue(metrics_.client_cert_cleared, 1);
    }
  }

  // Points tcp_proxy at the first matching route's cluster. False (connection
  // closed) when the filter state can't be set.
  bool route(const Login7& login) {
    const MssqlProxy::Route* match = MssqlProxy::selectRoute(*shared_.routing, login);
    if (match == nullptr) {
      handle_.incrementCounterValue(metrics_.unrouted, 1);
      return true;
    }
    if (!handle_.setFilterStateTyped("envoy.tcp_proxy.cluster", match->cluster)) {
      close(metrics_.protocol_errors, "mssql_proxy_route_error",
            "cannot set envoy.tcp_proxy.cluster to " + match->cluster);
      return false;
    }
    handle_.setMetadata(kMetadataNamespace, "cluster", match->cluster);
    handle_.incrementCounterValue(metrics_.routed, 1);
    DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: connection {} routed to {}",
            handle_.getConnectionId(), match->cluster);
    return true;
  }

  // LOGIN7 fields for access logs, e.g. %DYNAMIC_METADATA(mssql_proxy:user)%.
  // Never the password.
  void setLoginMetadata(const Login7& login) {
    const std::pair<std::string_view, const std::string&> fields[] = {
        {"user", login.user_name},         {"database", login.database},
        {"server_name", login.server_name}, {"app_name", login.app_name},
        {"client_host", login.host_name},   {"client_library", login.library_name},
    };
    for (const auto& [key, value] : fields) {
      handle_.setMetadata(kMetadataNamespace, key, value);
    }
    handle_.setMetadata(kMetadataNamespace, "auth",
                        std::string_view(login.integrated ? "integrated" : "sql"));
    handle_.setMetadata(kMetadataNamespace, "tds_version",
                        std::format("0x{:08x}", login.tds_version));
  }

  void closeOnError(const BridgeError& error) {
    switch (error.kind) {
    case BridgeError::Kind::Tls:
      close(metrics_.tls_errors, "mssql_proxy_tls_error", error.message);
      break;
    case BridgeError::Kind::Incompatible:
      close(metrics_.server_incompatible, "mssql_proxy_server_incompatible", error.message);
      break;
    case BridgeError::Kind::Protocol:
      close(metrics_.protocol_errors, "mssql_proxy_protocol_error", error.message);
      break;
    }
  }

  // details goes to the access log's connection termination details.
  void close(MetricID counter, std::string_view details, const std::string& reason) {
    handle_.incrementCounterValue(counter, 1);
    DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: closing connection {}: {}",
            handle_.getConnectionId(), reason);
    closed_ = true;
    handle_.closeWithDetails(NetworkConnectionCloseType::NoFlush, details);
  }

  // Counts what was learned about the connection, once each.
  void report(bool was_parsing, bool parsing, EncryptionMode mode, bool mars) {
    if (was_parsing && !parsing) {
      handle_.incrementCounterValue(metrics_.unparsed_connections, 1);
      DYM_LOG(handle_, LogLevel::Debug,
              "mssql_proxy: connection {} does not open with PRELOGIN; passing it through",
              handle_.getConnectionId());
    }
    if (mode_reported_ || mode == EncryptionMode::Unknown) {
      return;
    }
    mode_reported_ = true;
    switch (mode) {
    case EncryptionMode::None:
      handle_.incrementCounterValue(metrics_.encryption_none, 1);
      break;
    case EncryptionMode::LoginOnly:
      handle_.incrementCounterValue(metrics_.encryption_login_only, 1);
      break;
    case EncryptionMode::Full:
      handle_.incrementCounterValue(metrics_.encryption_full, 1);
      break;
    case EncryptionMode::Unknown:
      break;
    }
    if (mars) {
      handle_.incrementCounterValue(metrics_.mars_connections, 1);
    }
    DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: connection {} encryption {}, MARS {}",
            handle_.getConnectionId(), MssqlProxy::encryptionModeName(mode), mars);
  }

  NetworkFilterHandle& handle_;
  const Shared& shared_;   // Owned by the factory, which outlives the filter.
  const Metrics& metrics_; // shared_.metrics
  std::unique_ptr<ConnectionTracker> tracker_; // Observe-only mode.
  std::unique_ptr<TlsBridge> bridge_;          // TLS-terminating mode.
  bool mode_reported_ = false;
  bool tls_reported_ = false;
  bool client_cert_reported_ = false;
  bool login_reported_ = false;
  bool closed_ = false;
};

class MssqlProxyFilterFactory : public NetworkFilterFactory {
public:
  explicit MssqlProxyFilterFactory(Shared shared) : shared_(std::move(shared)) {}

  std::unique_ptr<NetworkFilter> create(NetworkFilterHandle& handle) override {
    return std::make_unique<MssqlProxyFilter>(handle, shared_);
  }

private:
  Shared shared_;
};

class MssqlProxyConfigFactory : public NetworkFilterConfigFactory {
public:
  std::unique_ptr<NetworkFilterFactory> create(NetworkFilterConfigHandle& handle,
                                               std::string_view config_view) override {
    std::string error;
    std::optional<MssqlProxy::FilterConfig> config =
        MssqlProxy::parseFilterConfig(config_view, MssqlProxy::readFile, error);
    if (!config) {
      DYM_LOG(handle, LogLevel::Error, "mssql_proxy: invalid filter_config: {}", error);
      return nullptr;
    }
    std::shared_ptr<const TlsContexts> tls;
    if (config->tls) {
      tls = TlsContexts::create(*config->tls, error);
      if (!tls) {
        DYM_LOG(handle, LogLevel::Error, "mssql_proxy: invalid TLS settings: {}", error);
        return nullptr;
      }
    }

    auto counter = [&](std::string_view name) { return handle.defineCounter(name).first; };
    Metrics metrics;
    metrics.connections = counter("mssql_proxy_connections_total");
    metrics.downstream_rx_bytes = counter("mssql_proxy_downstream_rx_bytes_total");
    metrics.upstream_rx_bytes = counter("mssql_proxy_upstream_rx_bytes_total");
    metrics.protocol_errors = counter("mssql_proxy_protocol_errors_total");
    metrics.tls_errors = counter("mssql_proxy_tls_errors_total");
    metrics.unparsed_connections = counter("mssql_proxy_unparsed_connections_total");
    metrics.encryption_none = counter("mssql_proxy_encryption_none_total");
    metrics.encryption_login_only = counter("mssql_proxy_encryption_login_only_total");
    metrics.encryption_full = counter("mssql_proxy_encryption_full_total");
    metrics.mars_connections = counter("mssql_proxy_mars_connections_total");
    metrics.tls_terminated = counter("mssql_proxy_tls_terminated_total");
    metrics.login7_seen = counter("mssql_proxy_login7_seen_total");
    metrics.client_cert_cleared = counter("mssql_proxy_client_cert_cleared_total");
    metrics.routed = counter("mssql_proxy_routed_total");
    metrics.unrouted = counter("mssql_proxy_unrouted_total");
    metrics.server_incompatible = counter("mssql_proxy_server_incompatible_total");
    return std::make_unique<MssqlProxyFilterFactory>(
        Shared{metrics, std::move(tls), std::move(config->routing)});
  }
};

REGISTER_NETWORK_FILTER_CONFIG_FACTORY(MssqlProxyConfigFactory, "mssql_proxy");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

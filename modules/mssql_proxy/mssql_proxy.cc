// mssql_proxy: MS SQL Server (TDS) proxy as a dynamic-module network filter.
//
// Network filter "mssql_proxy", placed in front of envoy.filters.network.tcp_proxy
// on the TDS 7.x filter chain (TDS 8.0 strict clients take a separate chain).
// Configured through filter_config (see config.h):
// - without "tls", it follows each connection's TDS framing and encryption
//   mode without changing any bytes (ConnectionTracker);
// - with "tls", it terminates TLS toward the client and opens its own toward
//   the server, so every message passes through in plain text (TlsBridge).
// Either way, connections whose framing is malformed or breaks the protocol
// are closed. LOGIN7 routing and authentication come in later phases (see
// plan.md).

#include <memory>
#include <string>
#include <string_view>

#include "config.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk_network.h"
#include "tds_connection.h"
#include "tls_bridge.h"

namespace Envoy {
namespace DynamicModules {
namespace {

using MssqlProxy::BridgeError;
using MssqlProxy::BridgeOutput;
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
};

class MssqlProxyFilter : public NetworkFilter {
public:
  MssqlProxyFilter(NetworkFilterHandle& handle, const Metrics& metrics,
                   std::shared_ptr<const TlsContexts> tls)
      : handle_(handle), metrics_(metrics) {
    if (tls) {
      bridge_ = std::make_unique<TlsBridge>(std::move(tls));
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
        const bool tls = error->kind == BridgeError::Kind::Tls;
        close(tls ? metrics_.tls_errors : metrics_.protocol_errors,
              tls ? "mssql_proxy_tls_error" : "mssql_proxy_protocol_error", error->message);
        data.drain(data.getSize());
        return NetworkFilterStatus::Stop;
      }
    }
    data.drain(data.getSize());
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

    report(was_parsing, bridge_->parsing(), bridge_->encryptionMode(), bridge_->marsEnabled());
    if (!tls_reported_ && bridge_->tlsEstablished()) {
      tls_reported_ = true;
      handle_.incrementCounterValue(metrics_.tls_terminated, 1);
    }
    if (!client_cert_reported_ && bridge_->clientCertCleared()) {
      client_cert_reported_ = true;
      handle_.incrementCounterValue(metrics_.client_cert_cleared, 1);
    }
    if (const uint64_t seen = bridge_->login7Messages(); seen > login7_reported_) {
      handle_.incrementCounterValue(metrics_.login7_seen, seen - login7_reported_);
      login7_reported_ = seen;
    }
    return NetworkFilterStatus::Continue;
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
  const Metrics& metrics_; // Owned by the factory, which outlives the filter.
  std::unique_ptr<ConnectionTracker> tracker_; // Observe-only mode.
  std::unique_ptr<TlsBridge> bridge_;          // TLS-terminating mode.
  bool mode_reported_ = false;
  bool tls_reported_ = false;
  bool client_cert_reported_ = false;
  uint64_t login7_reported_ = 0;
  bool closed_ = false;
};

class MssqlProxyFilterFactory : public NetworkFilterFactory {
public:
  MssqlProxyFilterFactory(Metrics metrics, std::shared_ptr<const TlsContexts> tls)
      : metrics_(metrics), tls_(std::move(tls)) {}

  std::unique_ptr<NetworkFilter> create(NetworkFilterHandle& handle) override {
    return std::make_unique<MssqlProxyFilter>(handle, metrics_, tls_);
  }

private:
  Metrics metrics_;
  std::shared_ptr<const TlsContexts> tls_; // Null when TLS isn't terminated.
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
    return std::make_unique<MssqlProxyFilterFactory>(metrics, std::move(tls));
  }
};

REGISTER_NETWORK_FILTER_CONFIG_FACTORY(MssqlProxyConfigFactory, "mssql_proxy");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

// mssql_proxy: MS SQL Server (TDS) proxy as a dynamic-module network filter.
//
// Network filter "mssql_proxy", placed in front of envoy.filters.network.tcp_proxy
// on the TDS 7.x filter chain (TDS 8.0 strict clients take a separate chain).
// It follows each connection's TDS framing and encryption mode without
// changing any bytes, and closes connections whose framing is malformed or
// breaks the protocol. PRELOGIN/TLS handling, LOGIN7 routing and
// authentication come in later phases (see plan.md).

#include <memory>
#include <string>
#include <string_view>

#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk_network.h"
#include "tds_connection.h"

namespace Envoy {
namespace DynamicModules {
namespace {

using MssqlProxy::ConnectionTracker;
using MssqlProxy::EncryptionMode;

struct Metrics {
  MetricID connections = 0;
  MetricID downstream_rx_bytes = 0; // client -> server
  MetricID upstream_rx_bytes = 0;   // server -> client
  MetricID protocol_errors = 0;
  MetricID unparsed_connections = 0; // Not TDS 7.x: passed through untouched.
  MetricID encryption_none = 0;
  MetricID encryption_login_only = 0;
  MetricID encryption_full = 0;
};

class MssqlProxyFilter : public NetworkFilter {
public:
  MssqlProxyFilter(NetworkFilterHandle& handle, const Metrics& metrics)
      : handle_(handle), metrics_(metrics) {}

  NetworkFilterStatus onNewConnection() override {
    handle_.incrementCounterValue(metrics_.connections, 1);
    return NetworkFilterStatus::Continue;
  }

  NetworkFilterStatus onRead(NetworkBuffer& data, bool) override {
    handle_.incrementCounterValue(metrics_.downstream_rx_bytes, data.getSize());
    return track(data, /*client=*/true);
  }

  NetworkFilterStatus onWrite(NetworkBuffer& data, bool) override {
    handle_.incrementCounterValue(metrics_.upstream_rx_bytes, data.getSize());
    return track(data, /*client=*/false);
  }

  void onEvent(NetworkConnectionEvent) override {}
  void onDestroy() override {}

private:
  NetworkFilterStatus track(NetworkBuffer& data, bool client) {
    if (closed_) {
      return NetworkFilterStatus::Stop;
    }
    const bool was_parsing = tracker_.parsing();
    for (const BufferView& chunk : data.getChunks()) {
      auto error = client ? tracker_.onClientData(chunk.toStringView())
                          : tracker_.onServerData(chunk.toStringView());
      if (error) {
        handle_.incrementCounterValue(metrics_.protocol_errors, 1);
        DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: closing connection {}: {}",
                handle_.getConnectionId(), *error);
        closed_ = true;
        handle_.closeWithDetails(NetworkConnectionCloseType::NoFlush,
                                 "mssql_proxy_protocol_error");
        return NetworkFilterStatus::Stop;
      }
    }
    if (was_parsing && !tracker_.parsing()) {
      handle_.incrementCounterValue(metrics_.unparsed_connections, 1);
      DYM_LOG(handle_, LogLevel::Debug,
              "mssql_proxy: connection {} does not open with PRELOGIN; passing it through",
              handle_.getConnectionId());
    }
    if (!mode_reported_ && tracker_.encryptionMode() != EncryptionMode::Unknown) {
      mode_reported_ = true;
      reportMode();
    }
    return NetworkFilterStatus::Continue;
  }

  void reportMode() {
    const EncryptionMode mode = tracker_.encryptionMode();
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
    DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: connection {} encryption {}, MARS {}",
            handle_.getConnectionId(), MssqlProxy::encryptionModeName(mode),
            tracker_.marsEnabled());
  }

  NetworkFilterHandle& handle_;
  const Metrics& metrics_; // Owned by the factory, which outlives the filter.
  ConnectionTracker tracker_;
  bool mode_reported_ = false;
  bool closed_ = false;
};

class MssqlProxyFilterFactory : public NetworkFilterFactory {
public:
  explicit MssqlProxyFilterFactory(Metrics metrics) : metrics_(metrics) {}

  std::unique_ptr<NetworkFilter> create(NetworkFilterHandle& handle) override {
    return std::make_unique<MssqlProxyFilter>(handle, metrics_);
  }

private:
  Metrics metrics_;
};

class MssqlProxyConfigFactory : public NetworkFilterConfigFactory {
public:
  std::unique_ptr<NetworkFilterFactory> create(NetworkFilterConfigHandle& handle,
                                               std::string_view) override {
    auto counter = [&](std::string_view name) { return handle.defineCounter(name).first; };
    Metrics metrics;
    metrics.connections = counter("mssql_proxy_connections_total");
    metrics.downstream_rx_bytes = counter("mssql_proxy_downstream_rx_bytes_total");
    metrics.upstream_rx_bytes = counter("mssql_proxy_upstream_rx_bytes_total");
    metrics.protocol_errors = counter("mssql_proxy_protocol_errors_total");
    metrics.unparsed_connections = counter("mssql_proxy_unparsed_connections_total");
    metrics.encryption_none = counter("mssql_proxy_encryption_none_total");
    metrics.encryption_login_only = counter("mssql_proxy_encryption_login_only_total");
    metrics.encryption_full = counter("mssql_proxy_encryption_full_total");
    return std::make_unique<MssqlProxyFilterFactory>(metrics);
  }
};

REGISTER_NETWORK_FILTER_CONFIG_FACTORY(MssqlProxyConfigFactory, "mssql_proxy");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

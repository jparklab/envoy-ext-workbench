// mssql_proxy: MS SQL Server (TDS) proxy as a dynamic-module network filter.
//
// Network filter "mssql_proxy", placed in front of envoy.filters.network.tcp_proxy.
// For now it passes all bytes through unchanged and counts connections and bytes in
// each direction. TDS framing, PRELOGIN/TLS, LOGIN7 parsing and backend selection
// come in later phases (see plan.md).

#include <memory>
#include <string>
#include <string_view>

#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk_network.h"

namespace Envoy {
namespace DynamicModules {
namespace {

struct Metrics {
  MetricID connections = 0;
  MetricID downstream_rx_bytes = 0; // client -> server
  MetricID upstream_rx_bytes = 0;   // server -> client
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
    return NetworkFilterStatus::Continue;
  }

  NetworkFilterStatus onWrite(NetworkBuffer& data, bool) override {
    handle_.incrementCounterValue(metrics_.upstream_rx_bytes, data.getSize());
    return NetworkFilterStatus::Continue;
  }

  void onEvent(NetworkConnectionEvent) override {}
  void onDestroy() override {}

private:
  NetworkFilterHandle& handle_;
  const Metrics& metrics_; // Owned by the factory, which outlives the filter.
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
    Metrics metrics;
    metrics.connections = handle.defineCounter("mssql_proxy_connections_total").first;
    metrics.downstream_rx_bytes =
        handle.defineCounter("mssql_proxy_downstream_rx_bytes_total").first;
    metrics.upstream_rx_bytes = handle.defineCounter("mssql_proxy_upstream_rx_bytes_total").first;
    return std::make_unique<MssqlProxyFilterFactory>(metrics);
  }
};

REGISTER_NETWORK_FILTER_CONFIG_FACTORY(MssqlProxyConfigFactory, "mssql_proxy");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

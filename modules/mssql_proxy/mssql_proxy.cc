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
// - with "auth", it applies a login policy (auth.h): refused logins get
//   error 18456 and the connection is closed without reaching the server;
//   with auth.kerberos read_ticket it reads Kerberos clients' principals from
//   their tickets with the service keytab (kerberos.h); with terminate it
//   authenticates Kerberos clients itself and logs in to the server with its
//   own Kerberos exchange (kerberos_terminate.h). Those GSS steps may block on
//   the KDC, so they run on a worker pool owned by the filter config, with the
//   connection's reads paused, and the filter resumes through its scheduler.
// LOGIN7 fields, the login method, the claimed identity and the login result
// go into dynamic metadata under "mssql_proxy" (see reportLogin), for access
// logs. Connections whose framing is malformed or breaks the protocol are
// closed.

#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "config.h"
#include "kerberos.h"
#include "kerberos_terminate.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"
#include "source/extensions/dynamic_modules/sdk/cpp/sdk_network.h"
#include "tds_connection.h"
#include "tls_bridge.h"
#include "worker_pool.h"

namespace Envoy {
namespace DynamicModules {
namespace {

using MssqlProxy::AuthSettings;
using MssqlProxy::BridgeError;
using MssqlProxy::BridgeOptions;
using MssqlProxy::BridgeOutput;
using MssqlProxy::Login7;
using MssqlProxy::LoginAuth;
using MssqlProxy::LoginMethod;
using MssqlProxy::LoginResult;
using MssqlProxy::RoutingConfig;
using MssqlProxy::ConnectionTracker;
using MssqlProxy::EncryptionMode;
using MssqlProxy::TlsBridge;
using MssqlProxy::TlsContexts;
using MssqlProxy::WorkerPool;

// Threads per filter config for Kerberos terminate's GSS steps.
constexpr size_t kKerberosWorkers = 4;

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
  MetricID login_succeeded = 0;     // The server accepted the login (LOGINACK).
  MetricID login_failed = 0;        // The server refused it.
  MetricID login_denied = 0;        // The proxy refused it.
  // Logins with a known outcome, by method.
  MetricID method_sql = 0;
  MetricID method_kerberos = 0;
  MetricID method_ntlm = 0;
  MetricID method_integrated = 0; // Mechanism not recognised.
  MetricID method_federated = 0;
};

// Settings shared by every connection of one filter config.
struct Shared {
  Metrics metrics;
  std::shared_ptr<const TlsContexts> tls; // Null when TLS isn't terminated.
  std::optional<RoutingConfig> routing;   // Set when routing on LOGIN7.
  std::shared_ptr<const AuthSettings> auth; // Null: no login policy.
  std::shared_ptr<WorkerPool> workers;      // Kerberos terminate's GSS steps.
};

constexpr std::string_view kMetadataNamespace = "mssql_proxy";

class MssqlProxyFilter : public NetworkFilter {
public:
  MssqlProxyFilter(NetworkFilterHandle& handle, const Shared& shared)
      : handle_(handle), shared_(shared), metrics_(shared.metrics) {
    if (shared.tls) {
      bridge_ = std::make_unique<TlsBridge>(
          shared.tls, BridgeOptions{.answer_prelogin = shared.routing.has_value(),
                                    .auth = shared.auth});
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
        data.drain(data.getSize());
        reportLogin();
        if (error->kind == BridgeError::Kind::Denied && !out.to_client.empty()) {
          handle_.injectWriteData(out.to_client, false); // The refusal.
        }
        closeOnError(*error);
        return NetworkFilterStatus::Stop;
      }
    }
    data.drain(data.getSize());
    reportLogin();
    if (!maybeRoute()) {
      return NetworkFilterStatus::Stop;
    }
    if (shared_.routing && bridge_->parsing() && !bridge_->upstreamStarted()) {
      // Nothing may reach tcp_proxy before routing: its first data, even
      // empty, makes it pick the cluster and connect.
      if (!out.to_client.empty()) {
        handle_.injectWriteData(out.to_client, false);
      }
      reportBridge(was_parsing);
      startWork();
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
    startWork();
    return NetworkFilterStatus::Continue;
  }

  // Kerberos terminate: runs the bridge's pending GSS step on the worker pool,
  // with the client's reads paused; the result comes back on this
  // connection's thread through the scheduler, unless it closed meanwhile.
  void startWork() {
    if (!bridge_->waiting()) {
      return;
    }
    std::function<void()> work = bridge_->takeWork();
    if (!work) {
      return; // Already running.
    }
    if (!shared_.workers) {
      close(metrics_.protocol_errors, "mssql_proxy_protocol_error", "no Kerberos workers");
      return;
    }
    handle_.readDisable(true);
    std::shared_ptr<Scheduler> scheduler = handle_.getScheduler();
    shared_.workers->post([work = std::move(work), scheduler, alive = std::weak_ptr<bool>(alive_),
                           this] {
      work();
      scheduler->schedule([alive, this] {
        if (alive.lock()) {
          resumeBridge();
        }
      });
    });
  }

  void resumeBridge() {
    if (closed_) {
      return;
    }
    handle_.readDisable(false);
    BridgeOutput out;
    std::optional<BridgeError> error = bridge_->resume(out);
    reportLogin();
    if (error) {
      if (error->kind == BridgeError::Kind::Denied && !out.to_client.empty()) {
        handle_.injectWriteData(out.to_client, false); // The refusal.
      }
      closeOnError(*error);
      return;
    }
    if (!maybeRoute()) {
      return;
    }
    if (!out.to_server.empty()) {
      handle_.injectReadData(out.to_server, false);
    }
    if (!out.to_client.empty()) {
      handle_.injectWriteData(out.to_client, false);
    }
    reportBridge(bridge_->parsing());
    startWork();
  }

  // With routing, picks the cluster once the bridge is about to open the
  // server's leg (the login's identity is then final). False when the
  // connection was closed.
  bool maybeRoute() {
    if (!shared_.routing || routed_ || !bridge_->upstreamStarted() || !bridge_->login()) {
      return true;
    }
    routed_ = true;
    return route(*bridge_->login());
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
    const MssqlProxy::Route* match =
        MssqlProxy::selectRoute(*shared_.routing, login, bridge_->auth().kerberosPrincipal());
    if (match == nullptr) {
      handle_.incrementCounterValue(metrics_.unrouted, 1);
      return true;
    }
    if (shared_.auth && shared_.auth->terminate) {
      bridge_->setUpstreamSpn(shared_.auth->terminate->spnFor(match->cluster));
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

  // Records what the bridge learned about the login since the last call.
  // True when LOGIN7 was read just now.
  bool reportLogin() {
    bool new_login = false;
    if (!login_reported_ && bridge_->login()) {
      login_reported_ = true;
      new_login = true;
      handle_.incrementCounterValue(metrics_.login7_seen, 1);
      setLoginMetadata(*bridge_->login());
    }
    const LoginAuth& auth = bridge_->auth();
    if (auth.method() && auth.method() != method_reported_) {
      method_reported_ = auth.method();
      handle_.setMetadata(kMetadataNamespace, "auth",
                          std::string_view(MssqlProxy::loginMethodName(*auth.method())));
    }
    if (auth.identity() != identity_reported_) {
      identity_reported_ = auth.identity();
      handle_.setMetadata(kMetadataNamespace, "identity", std::string_view(identity_reported_));
    }
    if (!result_reported_ && auth.result() != LoginResult::Pending) {
      result_reported_ = true;
      const char* result = MssqlProxy::loginResultName(auth.result());
      handle_.setMetadata(kMetadataNamespace, "login_result", std::string_view(result));
      if (auth.serverError()) {
        handle_.setMetadata(kMetadataNamespace, "server_error",
                            static_cast<double>(*auth.serverError()));
      }
      handle_.incrementCounterValue(auth.result() == LoginResult::Succeeded ? metrics_.login_succeeded
                                    : auth.result() == LoginResult::Failed  ? metrics_.login_failed
                                                                            : metrics_.login_denied,
                                    1);
      if (auth.method()) {
        handle_.incrementCounterValue(methodCounter(*auth.method()), 1);
      }
      DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: connection {} login {} ({}, '{}')",
              handle_.getConnectionId(), result,
              auth.method() ? MssqlProxy::loginMethodName(*auth.method()) : "?",
              auth.identity());
    }
    return new_login;
  }

  MetricID methodCounter(LoginMethod method) const {
    switch (method) {
    case LoginMethod::Sql:
      return metrics_.method_sql;
    case LoginMethod::Kerberos:
      return metrics_.method_kerberos;
    case LoginMethod::Ntlm:
      return metrics_.method_ntlm;
    case LoginMethod::Integrated:
      return metrics_.method_integrated;
    case LoginMethod::Federated:
      return metrics_.method_federated;
    }
    return metrics_.method_integrated;
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
    case BridgeError::Kind::Denied:
      // Counted as a login result; flush so the client reads the refusal.
      close(std::nullopt, "mssql_proxy_login_denied", error.message,
            NetworkConnectionCloseType::FlushWrite);
      break;
    }
  }

  // details goes to the access log's connection termination details.
  void close(std::optional<MetricID> counter, std::string_view details, const std::string& reason,
             NetworkConnectionCloseType type = NetworkConnectionCloseType::NoFlush) {
    if (counter) {
      handle_.incrementCounterValue(*counter, 1);
    }
    DYM_LOG(handle_, LogLevel::Debug, "mssql_proxy: closing connection {}: {}",
            handle_.getConnectionId(), reason);
    closed_ = true;
    handle_.closeWithDetails(type, details);
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
  std::optional<LoginMethod> method_reported_;
  std::string identity_reported_;
  bool result_reported_ = false;
  bool routed_ = false;
  bool closed_ = false;
  // Expires with the filter: a GSS step finishing later finds it gone.
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
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
    metrics.login_succeeded = counter("mssql_proxy_login_succeeded_total");
    metrics.login_failed = counter("mssql_proxy_login_failed_total");
    metrics.login_denied = counter("mssql_proxy_login_denied_total");
    metrics.method_sql = counter("mssql_proxy_login_sql_total");
    metrics.method_kerberos = counter("mssql_proxy_login_kerberos_total");
    metrics.method_ntlm = counter("mssql_proxy_login_ntlm_total");
    metrics.method_integrated = counter("mssql_proxy_login_integrated_total");
    metrics.method_federated = counter("mssql_proxy_login_federated_total");
    std::shared_ptr<const AuthSettings> auth;
    std::shared_ptr<WorkerPool> workers;
    if (config->auth) {
      if (const auto& k = config->kerberos; k && k->terminate) {
        auto terminator = MssqlProxy::GssTerminator::create(
            {.keytab_path = k->keytab_path,
             .delegate = k->delegate,
             .client_keytab_path = k->client_keytab_path,
             .principal = k->principal},
            error);
        if (!terminator) {
          DYM_LOG(handle, LogLevel::Error, "mssql_proxy: invalid Kerberos settings: {}", error);
          return nullptr;
        }
        if (!terminator->startupWarning().empty()) {
          DYM_LOG(handle, LogLevel::Warn, "mssql_proxy: Kerberos terminate: {}",
                  terminator->startupWarning());
        }
        config->auth->terminate = MssqlProxy::KerberosTerminate{
            .terminator = std::move(terminator),
            .spn = k->spn,
            .cluster_spns = k->cluster_spns,
            .channel_binding = k->channel_binding,
        };
        workers = std::make_shared<WorkerPool>(kKerberosWorkers);
      } else if (k) {
        config->auth->kerberos = MssqlProxy::KeytabTicketReader::create(k->keytab_path, error);
        if (!config->auth->kerberos) {
          DYM_LOG(handle, LogLevel::Error, "mssql_proxy: invalid Kerberos settings: {}", error);
          return nullptr;
        }
      }
      auth = std::make_shared<const AuthSettings>(std::move(*config->auth));
    }
    return std::make_unique<MssqlProxyFilterFactory>(Shared{
        metrics, std::move(tls), std::move(config->routing), std::move(auth), std::move(workers)});
  }
};

REGISTER_NETWORK_FILTER_CONFIG_FACTORY(MssqlProxyConfigFactory, "mssql_proxy");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

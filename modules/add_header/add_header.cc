// add_header: starter dynamic module with one HTTP filter.
//
// Filter name "add_header": adds the response header `x-workbench` with the
// filter_config string as its value (default "hello"). Replace it with real
// logic; see envoy/test/extensions/dynamic_modules/test_data/cpp/http.cc for
// more SDK examples.

#include <memory>
#include <string>
#include <string_view>

#include "source/extensions/dynamic_modules/sdk/cpp/sdk.h"

namespace Envoy {
namespace DynamicModules {
namespace {

class AddHeaderFilter : public HttpFilter {
public:
  explicit AddHeaderFilter(const std::string& value) : value_(value) {}

  HeadersStatus onRequestHeaders(HeaderMap&, bool) override { return HeadersStatus::Continue; }
  BodyStatus onRequestBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onRequestTrailers(HeaderMap&) override { return TrailersStatus::Continue; }

  HeadersStatus onResponseHeaders(HeaderMap& headers, bool) override {
    headers.set("x-workbench", value_);
    return HeadersStatus::Continue;
  }

  BodyStatus onResponseBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onResponseTrailers(HeaderMap&) override { return TrailersStatus::Continue; }
  void onStreamComplete() override {}
  void onDestroy() override {}

private:
  const std::string& value_; // Owned by the factory, which outlives the filter.
};

class AddHeaderFilterFactory : public HttpFilterFactory {
public:
  explicit AddHeaderFilterFactory(std::string value) : value_(std::move(value)) {}

  std::unique_ptr<HttpFilter> create(HttpFilterHandle&) override {
    return std::make_unique<AddHeaderFilter>(value_);
  }

private:
  std::string value_;
};

class AddHeaderConfigFactory : public HttpFilterConfigFactory {
public:
  std::unique_ptr<HttpFilterFactory> create(HttpFilterConfigHandle&,
                                            std::string_view config) override {
    return std::make_unique<AddHeaderFilterFactory>(config.empty() ? "hello"
                                                                   : std::string(config));
  }
};

REGISTER_HTTP_FILTER_CONFIG_FACTORY(AddHeaderConfigFactory, "add_header");

} // namespace
} // namespace DynamicModules
} // namespace Envoy

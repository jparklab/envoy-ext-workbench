# Builds libworkbench.so, an Envoy dynamic module, with the C++ SDK compiled
# straight from the pinned envoy/ submodule. The SDK needs only the standard
# library and abi.h, so this doesn't need Bazel. Envoy checks a hash of abi.h at
# load time, so the module must be built from the same submodule as the binary.
cmake_minimum_required(VERSION 3.20)
project(workbench_module CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

get_filename_component(ENVOY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../envoy" ABSOLUTE)
set(SDK_DIR "${ENVOY_ROOT}/source/extensions/dynamic_modules/sdk/cpp")

# Same sources as the SDK's Bazel targets :sdk and :sdk_abi.
file(GLOB SDK_SOURCES CONFIGURE_DEPENDS "${SDK_DIR}/sdk*.cc")

add_library(workbench SHARED
  src/filter.cc
  ${SDK_SOURCES}
)
target_include_directories(workbench PRIVATE "${ENVOY_ROOT}")
target_compile_options(workbench PRIVATE -Wall -Wextra -Wno-unused-parameter)
# The envoy_dynamic_module_callback_* symbols stay undefined here; the Envoy
# binary exports them and dlopen resolves them when the module is loaded.

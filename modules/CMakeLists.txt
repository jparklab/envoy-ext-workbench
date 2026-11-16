# Builds every Envoy dynamic module under modules/. Each subdirectory with a
# CMakeLists.txt is one module and calls envoy_dynamic_module(<name> <sources>),
# which produces lib<name>.so in the build directory; Envoy loads it by <name>.
#
# The C++ SDK is compiled once, straight from the pinned envoy/ submodule (it
# needs only the standard library and abi.h, so no Bazel). Envoy checks a hash
# of abi.h at load time, so modules must be built from the same submodule commit
# as the binary.
cmake_minimum_required(VERSION 3.20)
project(envoy_ext_modules CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# All modules land in one directory, so one ENVOY_DYNAMIC_MODULES_SEARCH_PATH covers them.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

get_filename_component(ENVOY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../envoy" ABSOLUTE)
set(SDK_DIR "${ENVOY_ROOT}/source/extensions/dynamic_modules/sdk/cpp")

# Same sources as the SDK's Bazel targets :sdk and :sdk_abi. An OBJECT library,
# not a static one, so every object is linked in: the SDK relies on static
# registration and ABI exports that nothing references directly.
file(GLOB SDK_SOURCES CONFIGURE_DEPENDS "${SDK_DIR}/sdk*.cc")
add_library(envoy_dynamic_modules_sdk OBJECT ${SDK_SOURCES})
target_include_directories(envoy_dynamic_modules_sdk PUBLIC "${ENVOY_ROOT}")

function(envoy_dynamic_module name)
  add_library(${name} SHARED ${ARGN})
  target_link_libraries(${name} PRIVATE envoy_dynamic_modules_sdk)
  target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  # The envoy_dynamic_module_callback_* symbols stay undefined here; the Envoy
  # binary exports them and dlopen resolves them when the module is loaded.
endfunction()

file(GLOB MODULE_DIRS LIST_DIRECTORIES true CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*")
foreach(dir IN LISTS MODULE_DIRS)
  if(EXISTS "${dir}/CMakeLists.txt")
    add_subdirectory("${dir}")
  endif()
endforeach()

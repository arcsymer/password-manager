cmake_minimum_required(VERSION 3.16)
project(password-manager
    VERSION     1.0.0
    DESCRIPTION "Portfolio password manager — libsodium + TOTP"
    LANGUAGES   CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# libsodium via pkg-config (apt package: libsodium-dev)
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ---------------------------------------------------------------------------
# Sub-projects
# ---------------------------------------------------------------------------
add_subdirectory(core)
add_subdirectory(cli)

# ---------------------------------------------------------------------------
# Tests — enabled by default; turn off with -DBUILD_TESTING=OFF
# ---------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

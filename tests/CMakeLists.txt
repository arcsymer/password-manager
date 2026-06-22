include(FetchContent)

# ---------------------------------------------------------------------------
# Catch2 v3 — fetched at configure time, not a system dependency.
# ---------------------------------------------------------------------------
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.4
)
FetchContent_MakeAvailable(Catch2)

# ---------------------------------------------------------------------------
# Test executable
# ---------------------------------------------------------------------------
add_executable(pwman-tests
    test_totp.cpp
    test_base32.cpp
    test_crypto.cpp
    test_vault.cpp
    test_vault_update.cpp
    test_strength.cpp
    test_export_import.cpp
)

target_compile_features(pwman-tests PRIVATE cxx_std_17)
target_compile_options(pwman-tests PRIVATE -Wall -Wextra)

target_link_libraries(pwman-tests
    PRIVATE
        pwman-core
        Catch2::Catch2WithMain
)

# ---------------------------------------------------------------------------
# CTest integration via Catch2's CMake module
# ---------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(pwman-tests)

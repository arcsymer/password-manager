add_library(pwman-core STATIC
    src/vault.cpp
    src/crypto.cpp
    src/totp.cpp
    src/generator.cpp
)

target_include_directories(pwman-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(pwman-core PUBLIC cxx_std_17)

target_compile_options(pwman-core PRIVATE -Wall -Wextra)

# Link against libsodium (found by PkgConfig in the top-level CMakeLists).
target_link_libraries(pwman-core PUBLIC ${SODIUM_LIBRARIES})
target_include_directories(pwman-core PUBLIC ${SODIUM_INCLUDE_DIRS})
target_compile_options(pwman-core PUBLIC ${SODIUM_CFLAGS_OTHER})

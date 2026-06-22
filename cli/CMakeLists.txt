add_executable(pwman-cli src/main.cpp)

target_compile_features(pwman-cli PRIVATE cxx_std_17)
target_compile_options(pwman-cli PRIVATE -Wall -Wextra)

target_link_libraries(pwman-cli PRIVATE pwman-core)

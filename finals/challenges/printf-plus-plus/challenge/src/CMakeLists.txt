cmake_minimum_required(VERSION 3.22)
project(challenge)
add_subdirectory(fmt EXCLUDE_FROM_ALL)

add_executable(challenge challenge.cpp)
target_link_libraries(challenge fmt::fmt fmt::fmt-header-only)

target_compile_options(challenge PUBLIC
    "-O0"
    "-g"
    "-fno-stack-protector"
    "-fno-exceptions"
    "-Wall"
)

# 32-bit so that the exploits don't have to deal with nul bytes
# Because format strings are stupid
set_target_properties(challenge PROPERTIES
    COMPILE_FLAGS "-m32"
    LINK_FLAGS "-m32"
)

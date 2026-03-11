set(PROJECT_NAMESPACE "tuposoft")

set(BASE_PROJECT_NAME "asio_dns_resolver")
set(TEST_PROJECT_NAME "${BASE_PROJECT_NAME}_test")
set(STANDALONE_PROJECT_NAME "${BASE_PROJECT_NAME}_exec")

set(PROJECT_DESCRIPTION "Asynchronous DNS Resolver written in C++ based on ASIO")
set(PROJECT_VERSION 0.0.3.0)

set(CMAKE_MINIMUM_REQUIRED_VERSION 3.24)
set(CMAKE_PROJECT_HOMEPAGE_URL https://tuposoft.com)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CPM_VERSION "0.42.1")
set(CPM_HASH "f3a6dcc6a04ce9e7f51a127307fa4f699fb2bade357a8eb4c5b45df76e1dc6a5")
set(CPM_URL "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${CPM_VERSION}/CPM.cmake")

file(
        DOWNLOAD
        ${CPM_URL}
        ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
        EXPECTED_HASH SHA256=${CPM_HASH}
)
include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)

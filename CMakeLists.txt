include(cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${BASE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(
            FATAL_ERROR
            "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
    )
endif ()

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

CPMAddPackage("gh:fmtlib/fmt#10.2.1")

set(BOOST_INCLUDE_LIBRARIES "asio")
set(BOOST_SKIP_INSTALL_RULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
CPMAddPackage(
        NAME Boost
        VERSION 1.85.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
)

set(LIBRARIES "fmt::fmt" "boost_asio")
if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0A00)
    list(APPEND LIBRARIES "ws2_32" "wsock32")
endif ()

add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS} $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.11.2")

packageProject(
        NAME ${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        NAMESPACE ${PROJECT_NAMESPACE}
        BINARY_DIR ${PROJECT_BINARY_DIR}
        INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
        INCLUDE_HEADER_PATTERN "resolver.h"
        INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
        EXPORT_HEADER "${PROJECT_NAME}/export.h"
        DEPENDENCIES "fmt 10.2.1;boost 1.85.0"
)

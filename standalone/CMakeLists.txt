include(../cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

project(${STANDALONE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

set(BOOST_INCLUDE_LIBRARIES "beast;url")
set(BOOST_SKIP_INSTALL_RULES OFF)
CPMAddPackage(
        NAME Boost
        VERSION 1.85.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
)
CPMAddPackage(NAME ${BASE_PROJECT_NAME} SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAMESPACE}::${BASE_PROJECT_NAME} Boost::beast Boost::url)
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS})

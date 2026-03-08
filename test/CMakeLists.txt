include(../cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${TEST_PROJECT_NAME} VERSION ${PROJECT_VERSION})

if (${WIN32})
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif ()

CPMAddPackage("gh:google/googletest@1.14.0")

CPMAddPackage(
        NAME ${BASE_PROJECT_NAME}
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..
)

enable_testing()

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp)

add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAMESPACE}::${BASE_PROJECT_NAME} gtest_main gmock)
target_include_directories(${PROJECT_NAME} PRIVATE include)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})

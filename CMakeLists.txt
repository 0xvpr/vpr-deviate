cmake_minimum_required( VERSION 3.15 )

if(MSVC)
    message( FATAL_ERROR "Cannot be used with MSVC. Use MinGW" )
endif()

set( CMAKE_C_STANDARD             99 )
set( CMAKE_C_STANDARD_REQUIRED    ON )
set( CMAKE_C_EXTENSIONS          OFF )

set( CMAKE_CXX_STANDARD           17 )
set( CMAKE_CXX_STANDARD_REQUIRED  ON )
set( CMAKE_CXX_EXTENSIONS        OFF )

project(
  vpr-deviate
    VERSION 1.0.1
    DESCRIPTION "vpr-deviate: a C99/C++17 Header only library for dependency free function hooking in windows (MinGW only)"
    LANGUAGES C CXX
)

include(GNUInstallDirs)

add_library(vpr-deviate INTERFACE)

target_include_directories(
  vpr-deviate INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>    # When building from this source dir
    $<INSTALL_INTERFACE:include>                              # When installed on a system
)

add_library(vpr-deviate::deviate ALIAS vpr-deviate)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
  TARGETS vpr-deviate
  EXPORT vpr-deviate-targets
)

install(
  EXPORT vpr-deviate-targets
  FILE vpr-deviate-targets.cmake
  NAMESPACE vpr-deviate::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vpr-deviate
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/vpr-deviate-config-version.cmake"
  VERSION       ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vpr-deviate-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/vpr-deviate-config.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/vpr-deviate"
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/vpr-deviate-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/vpr-deviate-config-version.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vpr-deviate
)

option(VPR_SHELL_BUILD_TESTS "Build tests" OFF)
if(VPR_SHELL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

include(CPack)

cmake_minimum_required(VERSION 3.13)
project(shadow_catcher)

set(BINARY_NAME "shadow_catcher")

cmake_policy(SET CMP0063 NEW)

set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Flutter build mode" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Profile" "Release")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")
add_subdirectory(${FLUTTER_MANAGED_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK REQUIRED IMPORTED_TARGET gtk+-3.0)

add_definitions(-DAPPLICATION_ID="com.shadowcatcher.app")

set(FLUTTER_ENGINE_DIR "/home/kali/flutter/bin/cache/artifacts/engine/linux-x64")

add_executable(${BINARY_NAME}
  "runner/main.cc"
  "runner/my_application.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

target_include_directories(${BINARY_NAME} PRIVATE
  "${FLUTTER_ENGINE_DIR}"
  "${FLUTTER_ENGINE_DIR}/flutter_linux"
  "${FLUTTER_MANAGED_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/runner"
)

apply_standard_settings(${BINARY_NAME})

target_compile_definitions(${BINARY_NAME} PRIVATE
  "$<$<CONFIG:Debug>:APPLICATION_ENVIRONMENT=\"debug\">"
  "$<$<CONFIG:Profile>:APPLICATION_ENVIRONMENT=\"profile\">"
  "$<$<CONFIG:Release>:APPLICATION_ENVIRONMENT=\"release\">"
)

target_link_libraries(${BINARY_NAME} PRIVATE
  flutter
  PkgConfig::GTK
)

install(TARGETS ${BINARY_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}")
install(
  FILES "${FLUTTER_ENGINE_DIR}/libflutter_linux_gtk.so"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
)
install(
  FILES "${FLUTTER_ENGINE_DIR}/icudtl.dat"
  DESTINATION "${CMAKE_INSTALL_PREFIX}"
)

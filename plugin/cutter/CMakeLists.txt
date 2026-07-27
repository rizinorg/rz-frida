cmake_minimum_required(VERSION 3.16)
project(cutter-frida-plugin)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CUTTER_INSTALL_PLUGDIR "share/rizin/cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake/Cutter")

find_package(Cutter REQUIRED)

add_library(cutter_frida_plugin MODULE
    src/FridaCmdRunner.cpp
    src/FridaCmdRunner.h
    src/FridaConnectDialog.cpp
    src/FridaConnectDialog.h
    src/FridaDescriptions.h
    src/FridaDockWidget.cpp
    src/FridaDockWidget.h
    src/FridaPlugin.cpp
    src/FridaPlugin.h
)

target_link_libraries(cutter_frida_plugin PRIVATE Cutter::Cutter)
install(TARGETS cutter_frida_plugin DESTINATION "${CUTTER_INSTALL_PLUGDIR}")


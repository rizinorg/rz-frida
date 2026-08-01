cmake_minimum_required(VERSION 3.16)
project(cutter-frida-plugin)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CUTTER_INSTALL_PLUGDIR "share/rizin/cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake/Cutter")

find_package(Cutter REQUIRED)
find_package(Qt5 QUIET COMPONENTS Widgets Concurrent)
if(NOT Qt5_FOUND)
	find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent)
	set(QT_WIDGETS Qt6::Widgets)
	set(QT_CONCURRENT Qt6::Concurrent)
else()
	set(QT_WIDGETS Qt5::Widgets)
	set(QT_CONCURRENT Qt5::Concurrent)
endif()
find_package(PkgConfig REQUIRED)

# rizin core headers from Cutter SDK
pkg_check_modules(RZ_CORE REQUIRED rz_core)

set(RZ_FRIDA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "Path to rz-frida source root")

# rizin dlopens cutter's plugin dir
get_target_property(CUTTER_RIZIN_INCS Cutter::Rizin INTERFACE_INCLUDE_DIRECTORIES)
if(CUTTER_RIZIN_INCS)
	list(GET CUTTER_RIZIN_INCS 0 CUTTER_RIZIN_INC)
	get_filename_component(CUTTER_SDK_PREFIX "${CUTTER_RIZIN_INC}" DIRECTORY)
	get_filename_component(CUTTER_SDK_PREFIX "${CUTTER_SDK_PREFIX}" DIRECTORY)
	set(RZ_FRIDA_PLUGIN_DIR "${CUTTER_SDK_PREFIX}/lib/rizin/plugins")
else()
	set(RZ_FRIDA_PLUGIN_DIR "${RZ_FRIDA_SOURCE_DIR}/build-cutter-rizin/plugin/rizin")
endif()
find_library(RZ_FRIDA_LIBRARY rz_frida
	PATHS
		"${RZ_FRIDA_PLUGIN_DIR}"
		"${RZ_FRIDA_SOURCE_DIR}/build-cutter-rizin/plugin/rizin"
		"${RZ_FRIDA_SOURCE_DIR}/build-frida/plugin/rizin"
		"${RZ_FRIDA_SOURCE_DIR}/build/plugin/rizin"
	NO_DEFAULT_PATH
)
if(NOT RZ_FRIDA_LIBRARY)
	find_library(RZ_FRIDA_LIBRARY rz_frida REQUIRED)
endif()
get_filename_component(RZ_FRIDA_RUNPATH "${RZ_FRIDA_LIBRARY}" DIRECTORY)

add_library(cutter_frida_plugin MODULE
	src/FridaApiBridge.cpp
	src/FridaApiBridge.h
	src/FridaConnectDialog.cpp
	src/FridaConnectDialog.h
	src/FridaDescriptions.h
	src/FridaDockWidget.cpp
	src/FridaDockWidget.h
	src/FridaPlugin.cpp
	src/FridaPlugin.h
	src/FridaTaskRunner.cpp
	src/FridaTaskRunner.h
)

target_include_directories(cutter_frida_plugin PRIVATE
	"${RZ_FRIDA_SOURCE_DIR}/plugin/rizin/include"
	${RZ_CORE_INCLUDE_DIRS}
)

target_link_libraries(cutter_frida_plugin PRIVATE
	Cutter::Cutter
	${QT_WIDGETS}
	${QT_CONCURRENT}
	${RZ_FRIDA_LIBRARY}
	${RZ_CORE_LIBRARIES}
)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
set(CMAKE_BUILD_RPATH_USE_LINK_PATH FALSE)
set_target_properties(cutter_frida_plugin PROPERTIES
	BUILD_WITH_INSTALL_RPATH TRUE
	INSTALL_RPATH "${RZ_FRIDA_RUNPATH}"
)

install(TARGETS cutter_frida_plugin DESTINATION "${CUTTER_INSTALL_PLUGDIR}")

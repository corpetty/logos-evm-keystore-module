cmake_minimum_required(VERSION 3.14)
project(KeystoreModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

logos_module(NAME keystore_module)

# Export only Qt's plugin entry points, as Windows already does: the Rust core, libsecp256k1
# and the statically linked SDK stay inside the plugin rather than clashing with another copy.
if(APPLE)
    target_link_options(keystore_module_module_plugin PRIVATE
        "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports/keystore_module.exp")
elseif(UNIX)
    target_link_options(keystore_module_module_plugin PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports/keystore_module.map")
endif()

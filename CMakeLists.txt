cmake_minimum_required(VERSION 3.20)
project(TrafficMonitorIpPlugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

function(configure_cpp_target target)
    target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    if(MSVC)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
            $<$<COMPILE_LANGUAGE:CXX>:/W4>)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    if(WIN32)
        target_compile_definitions(${target} PRIVATE
            UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    endif()
endfunction()

if(BUILD_TESTING)
    foreach(test IN ITEMS external_ip_cache claude_risk ip_text_provider)
        add_executable(${test}_tests tests/${test}_tests.cpp)
        configure_cpp_target(${test}_tests)
        add_test(NAME ${test} COMMAND ${test}_tests)
    endforeach()

    if(WIN32)
        add_executable(exit_detection_tests
            tests/exit_detection_tests.cpp
            src/exit_detection.cpp)
        configure_cpp_target(exit_detection_tests)
        target_link_libraries(exit_detection_tests PRIVATE winhttp)
        add_test(NAME exit_detection COMMAND exit_detection_tests)

        add_executable(claude_runtime_tests tests/claude_runtime_tests.cpp)
        configure_cpp_target(claude_runtime_tests)
        target_link_libraries(claude_runtime_tests PRIVATE winhttp)
        add_test(NAME claude_runtime COMMAND claude_runtime_tests)

        add_executable(plugin_persistence_tests tests/plugin_persistence_tests.cpp)
        configure_cpp_target(plugin_persistence_tests)
        target_include_directories(plugin_persistence_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(plugin_persistence_tests PRIVATE shlwapi user32 gdi32)
        if(MINGW)
            target_link_options(plugin_persistence_tests PRIVATE -municode)
        endif()
        add_test(NAME plugin_persistence COMMAND plugin_persistence_tests)
        set_tests_properties(plugin_persistence PROPERTIES TIMEOUT 180)
    endif()
endif()

if(WIN32)
    enable_language(RC)
    add_library(TrafficMonitorIpPlugin SHARED
        src/dllmain.cpp
        src/claude_risk.cpp
        src/exit_detection.cpp
        src/ip_utils.cpp
        src/options_dialog.cpp
        src/plugin.cpp
        src/proxy_watch.cpp
        res/plugin.rc)
    configure_cpp_target(TrafficMonitorIpPlugin)
    target_include_directories(TrafficMonitorIpPlugin PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/res")
    target_link_libraries(TrafficMonitorIpPlugin PRIVATE
        iphlpapi ws2_32 winhttp shlwapi user32 gdi32)
    set_target_properties(TrafficMonitorIpPlugin PROPERTIES PREFIX "")
endif()

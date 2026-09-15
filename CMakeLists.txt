cmake_minimum_required(VERSION 3.24)
project(JustScannerMockCore VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(just_scanner_core STATIC
    src/scanner_backend_policy.cpp
    src/scanner_core.cpp
    src/wia2_backend.cpp
    src/wia_capability_model.cpp
    src/wia_com_worker.cpp
    src/wia_discovery_model.cpp
    src/wia_transfer_model.cpp
    src/wia_worker_model.cpp
    src/wsd_discovery_model.cpp
    src/wsd_http_transport.cpp
    src/wsd_job_codec.cpp
    src/wsd_scan_model.cpp
    src/wsd_soap_codec.cpp
)
target_include_directories(just_scanner_core PUBLIC src)
target_compile_definitions(just_scanner_core PRIVATE UNICODE _UNICODE NOMINMAX)
if(WIN32)
    target_link_libraries(just_scanner_core PUBLIC windowscodecs ole32 oleaut32 wiaguid xmllite winhttp)
endif()
if(MSVC)
    target_compile_options(just_scanner_core PRIVATE /W4 /WX /permissive- /utf-8)
endif()

add_executable(just_scanner_tests tests/test_main.cpp)
target_link_libraries(just_scanner_tests PRIVATE just_scanner_core)
if(MSVC)
    target_compile_options(just_scanner_tests PRIVATE /W4 /WX /permissive- /utf-8)
endif()

if(WIN32)
    add_executable(just_scanner_app WIN32 src/mock_gui.cpp)
    target_link_libraries(just_scanner_app PRIVATE just_scanner_core comctl32 user32 gdi32 shell32)
    target_compile_definitions(just_scanner_app PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(just_scanner_app PRIVATE /W4 /WX /permissive- /utf-8)
    endif()
endif()

enable_testing()
add_test(
    NAME just_scanner_mock_core
    COMMAND just_scanner_tests "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/sanitized"
)

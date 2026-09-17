@echo off
setlocal
cd /d "%~dp0"

call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist build-native mkdir build-native

cl /nologo /std:c++20 /EHsc /O2 /MT /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DNOMINMAX /Isrc src\scanner_backend_policy.cpp src\scanner_core.cpp src\wia2_backend.cpp src\wia_capability_model.cpp src\wia_com_worker.cpp src\wia_discovery_model.cpp src\wia_item_tree_model.cpp src\wia_staged_transfer_adapter.cpp src\wia_staged_worker_backend.cpp src\wia_transfer_model.cpp src\wia_worker_model.cpp src\wsd_discovery_model.cpp src\wsd_http_transport.cpp src\wsd_job_codec.cpp src\wsd_job_transport.cpp src\wsd_job_session.cpp src\wsd_session_worker_backend.cpp src\wsd_job_worker.cpp src\wsd_job_worker_model.cpp src\wsd_scan_model.cpp src\wsd_soap_codec.cpp tests\test_main.cpp /Fo"build-native\\" /Fe"build-native\just_scanner_tests.exe" /link windowscodecs.lib ole32.lib oleaut32.lib wiaguid.lib xmllite.lib winhttp.lib
if errorlevel 1 exit /b %errorlevel%

build-native\just_scanner_tests.exe fixtures\sanitized
if errorlevel 1 exit /b %errorlevel%

cl /nologo /std:c++20 /EHsc /O2 /MT /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DNOMINMAX /Isrc /c src\mock_gui.cpp /Fo"build-native\mock_gui.obj"
if errorlevel 1 exit /b %errorlevel%

link /nologo /SUBSYSTEM:WINDOWS /OUT:"build-native\just_scanner_app.exe" build-native\scanner_backend_policy.obj build-native\scanner_core.obj build-native\wia2_backend.obj build-native\wia_capability_model.obj build-native\wia_com_worker.obj build-native\wia_discovery_model.obj build-native\wia_item_tree_model.obj build-native\wia_staged_transfer_adapter.obj build-native\wia_staged_worker_backend.obj build-native\wia_transfer_model.obj build-native\wia_worker_model.obj build-native\wsd_discovery_model.obj build-native\wsd_http_transport.obj build-native\wsd_job_codec.obj build-native\wsd_job_transport.obj build-native\wsd_job_session.obj build-native\wsd_session_worker_backend.obj build-native\wsd_job_worker.obj build-native\wsd_job_worker_model.obj build-native\wsd_scan_model.obj build-native\wsd_soap_codec.obj build-native\mock_gui.obj windowscodecs.lib ole32.lib oleaut32.lib wiaguid.lib xmllite.lib winhttp.lib comctl32.lib user32.lib gdi32.lib shell32.lib
if errorlevel 1 exit /b %errorlevel%

build-native\just_scanner_app.exe --self-check
exit /b %errorlevel%

project(scan_orchestrator_testtool)

file(GLOB VD_SCANNER_TESTTOOL_SRC
    "*.cpp"
    )

add_executable(scan_orchestrator_testtool
    ${VD_SCANNER_TESTTOOL_SRC}
    )

target_link_libraries(scan_orchestrator_testtool PUBLIC scan_orchestrator base httplib::httplib)


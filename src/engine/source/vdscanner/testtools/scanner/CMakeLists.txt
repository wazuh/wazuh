project(vdscanner_testtool)

file(GLOB VD_SCANNER_TESTTOOL_SRC
    "*.cpp"
    )

add_executable(vdscanner_testtool
    ${VD_SCANNER_TESTTOOL_SRC}
    )

target_link_libraries(vdscanner_testtool PUBLIC vdscanner base httplib::httplib)

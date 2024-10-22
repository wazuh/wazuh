project(vdscanner_tool)

file(GLOB VDSCANNER_TOOL_SRC
    "*.cpp"
    )

add_executable(${PROJECT_NAME}
    ${VDSCANNER_TOOL_SRC}
    )

target_link_libraries(${PROJECT_NAME} PUBLIC vdscanner base httplib::httplib)

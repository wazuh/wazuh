# embed_sql.cmake — generate a C file that defines a const char* from a SQL file
#
# Expected variables (passed via -D):
#   SQL_FILE  — input .sql path
#   OUT_FILE  — output .c path
#   VAR_NAME  — C variable name (e.g. schema_global_sql)

file(READ "${SQL_FILE}" SQL_CONTENT)

# Escape backslashes, then double-quotes, then collapse newlines
string(REPLACE "\\" "\\\\" SQL_CONTENT "${SQL_CONTENT}")
string(REPLACE "\"" "\\\"" SQL_CONTENT "${SQL_CONTENT}")
string(REPLACE "\n" "" SQL_CONTENT "${SQL_CONTENT}")

file(WRITE "${OUT_FILE}" "const char *${VAR_NAME} = \"${SQL_CONTENT}\";\n")

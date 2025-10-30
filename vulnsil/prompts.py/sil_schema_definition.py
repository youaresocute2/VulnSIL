# vulnsil/prompts/sil_schema_definition.py

SIL_SCHEMA_DEFINITION = """
## 1. 顶层结构
{
  "function_name": "string", 
  "return_type": "string",
  "parameters": [ /* Parameter Object */ ],
  "variables": [ /* Variable Object */ ],
  "operations": [ /* Operation Object */ ]
}
## 2. Parameter Object
{ 
  "name": "string", 
  "type": "string" /* e.g., "char*", "int", "FILE*" */ 
}
## 3. Variable Object
{
  "name": "string", 
  "type": "string" /* e.g., "char[100]", "wchar_t*", "SOCKET" */,
  "size_bytes": "integer | 'UNKNOWN'" /* e.g., 100, 'UNKNOWN' */
}
## 4. Operation Object (SIL 原语) 
### 4.1. `BUFFER_WRITE`
{
  "type": "BUFFER_WRITE", "function_call": "string" /* e.g., "strcpy", "memcpy", "memset", "wcsncat" */,
  "destination_variable": "string", 
  "source_variable": "string | null",
  "size_bytes_written": "integer | string | 'UNKNOWN'" /* e.g., 100, "100*sizeof(char)" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.2. `MEMORY_ALLOC`
{
  "type": "MEMORY_ALLOC", 
  "function_call": "string" /* e.g., "malloc", "calloc", "realloc", "ALLOCA" */,
  "size_variable_or_value": "string | integer", 
  "assigned_to_variable": "string",
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.3. `EXTERNAL_CALL` (污点源)
{
  "type": "EXTERNAL_CALL", 
  "function_call": "string" /* e.g., "GETENV", "recv", "fgets", "fscanf", "atoi", "RAND32" */,
  "stores_to_variable": "string", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.4. `CONDITION_CHECK` (安全检查)
{
  "type": "CONDITION_CHECK", 
  "checked_variable": "string | null",
  "check_type": "string" /* e.g., "NULL_CHECK", "BOUNDS_CHECK", "RETURN_VALUE_CHECK" */,
  "condition_expression": "string" /* e.g., "if (ptr != NULL)", "if (index >= 0 && index < 10)" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.5. `FUNCTION_CALL` (普通/格式化字符串)
{
  "type": "FUNCTION_CALL", 
  "function_call": "string" /* e.g., "goodG2B", "printf", "snprintf" */,
  "arguments": [ "string" ], 
  "is_format_string_sink": "boolean",
  "format_string_arg_index": "integer | null", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.6. `INTEGER_OPERATION` (整数运算/数组索引)
{
  "type": "INTEGER_OPERATION", 
  "operation_expression": "string" /* e.g., "count * 2", "100 / data", "buf[index]" */,
  "operands_variables": ["string"], 
  "assigned_to_variable": "string | null",
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.7. `POINTER_ARITHMETIC` (指针运算/解引用)
{
  "type": "POINTER_ARITHMETIC", 
  "variable": "string",
  "operation_expression": "string" /* e.g., "ptr += offset", "*ptr = 'A'", "printf(\"%s\", data)" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.8. `MEMORY_FREE` (内存释放)
{ 
  "type": "MEMORY_FREE", 
  "function_call": "string" /* "free" */, 
  "freed_variable": "string", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.9. `RESOURCE_ACQUIRE` (资源获取)
{
  "type": "RESOURCE_ACQUIRE", 
  "function_call": "string" /* e.g., "fopen", "open", "socket", "CreateFile" */,
  "assigned_to_variable": "string", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.10. `RESOURCE_RELEASE` (资源释放)
{
  "type": "RESOURCE_RELEASE", 
  "function_call": "string" /* e.g., "fclose", "close", "CloseHandle" */,
  "released_variable": "string", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.11. `COMMAND_EXECUTION` (命令执行)
{
  "type": "COMMAND_EXECUTION", 
  "function_call": "string" /* e.g., "system", "execlp" */,
  "command_variable": "string", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
### 4.12. `ASSIGNMENT` (赋值)
{
  "type": "ASSIGNMENT", 
  "destination_variable": "string",
  "source_variable_or_value": "string | number | null", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}
"""
# vulnsil/sil_schema.md

# VulnSIL: 语义中间语言 (SIL) 规范 V1.2 (最终扩展版)

本文档定义了 VulnSIL 框架中使用的“语义中间语言”(SIL) 的 JSON 结构。
`SIL Generator` (LLM) 的任务就是将 C/C++ 源代码转换为此格式。

## 1. 顶层结构 (Root Object)
{
  "function_name": "string",
  "return_type": "string",
  "parameters": [ /* Parameter Object */ ],
  "variables": [ /* Variable Object */ ],
  "operations": [ /* Operation Object */ ]
  // enrichment_analysis 字段由 sil_enricher.py 动态添加
}

---
## 2. Parameter Object (参数对象)
{
  "name": "string",
  "type": "string" 
  /* 示例: "char*", "int", "struct UserData*", "FILE*", "SOCKET", "HANDLE", "UNKNOWN_TYPE" */
}

---
## 3. Variable Object (局部变量对象)
{
  "name": "string",
  "type": "string" 
  /* 示例: "char[128]", "int", "void*", "FILE*", "wchar_t[100]", "struct _twoIntsStruct*" */,
  "size_bytes": "integer | 'UNKNOWN'" 
  /* 示例: 128 (对于 char[128]), 4 (对于 int), 'UNKNOWN' (对于 char*) */
  // element_type 未单独添加, 依赖 type 字段解析
}

---
## 4. Operation Object (核心：SIL 原语)

这是 SIL 的核心，用于捕获**安全关键 (Security-Critical)** 操作。

### 4.1. BUFFER_WRITE (缓冲区写入)
描述:任何向缓冲区写入数据的操作 (内存、字符串函数)。
{
    "type": "BUFFER_WRITE",
    "function_call": "string" /* e.g., "strcpy", "sprintf", "memcpy", "strncat", "memset", "wcsncpy", "wmemset" */,
    "destination_variable": "string" /* 变量名, e.g., "buffer", "data" */,
    "source_variable": "string | null" /* 变量名, e.g., "input", "src" (null for memset) */,
    "size_bytes_written": "integer | string | 'UNKNOWN'" /* e.g., 100, "100*sizeof(char)", src_len */,
    // 未添加 size_expr, 依赖 enricher 尝试解析 size_bytes_written
    "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
  }

### 4.2. MEMORY_ALLOC (内存分配)
描述: 动态内存/栈内存分配。
{
  "type": "MEMORY_ALLOC",
  "function_call": "string" /* e.g., "malloc", "calloc", "realloc", "ALLOCA" */,
  "size_variable_or_value": "string | integer" /* e.g., "size", 1024, "50*sizeof(wchar_t)" */,
  "assigned_to_variable": "string" /* e.g., "ptr", "data" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.3. EXTERNAL_CALL (外部调用 / 污点源)
描述: 任何可能引入外部（不可信）数据的函数调用。
{
  "type": "EXTERNAL_CALL",
  "function_call": "string" /* e.g., "read", "recv", "getenv", "GETENV", "fgets", "fscanf", "atoi", "RAND32" */,
  "stores_to_variable": "string" /* 外部数据存储到的变量, e.g., "userInput", "data", "environment" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.4. CONDITION_CHECK (条件检查)
描述: 关键的安全检查（空指针、边界、返回值等）。
{
  "type": "CONDITION_CHECK",
  "checked_variable": "string | null" /* e.g., "input", "data", "size", "pFile", null for return value check */,
  "check_type": "string" /* e.g., "NULL_CHECK", "LENGTH_CHECK", "BOUNDS_CHECK", "RETURN_VALUE_CHECK" */,
  "condition_expression": "string" /* e.g., "if (input != NULL)", "if (data >= 0 && data < 10)", "if (malloc(...) == NULL)" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.5. FUNCTION_CALL (普通/格式化字符串函数调用)
描述: 调用项目内的其他函数，或潜在危险的格式化字符串函数。
{
  "type": "FUNCTION_CALL",
  "function_call": "string" /* e.g., "goodG2B", "bad_sink", "printf", "snprintf", "vprintf", "_vsnwprintf" */,
  "arguments": [ "string" ] /* 传递的参数变量列表, e.g., ["data", "src", "%s"] */,
  "is_format_string_sink": "boolean", 
  "format_string_arg_index": "integer | null", 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
  // uses_tainted_data 由 enricher 动态添加
}

### 4.6. INTEGER_OPERATION (整数运算/数组索引)
描述: 潜在危险的整数算术或数组索引操作。
{
  "type": "INTEGER_OPERATION",
  "operation_expression": "string" /* e.g., "count * 2", "100 / data", "100 % data", "data_buf[data]" */,
  "operands_variables": ["string"] /* 参与运算/索引的变量, e.g., ["count"], ["data"] */,
  "assigned_to_variable": "string | null" /* e.g., "buffer_size", null if used directly */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.7. POINTER_ARITHMETIC (指针运算/解引用)
描述: 潜在危险的指针移动、解引用或用于函数调用。
{
  "type": "POINTER_ARITHMETIC",
  "variable": "string" /* e.g., "ptr", "data" */,
  "operation_expression": "string" /* e.g., "ptr += offset", "*ptr = 'A'", "ptr[0]", "->field", "printf(\"%s\", data)" */, 
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.8. MEMORY_FREE (内存释放)
描述: 释放动态分配的内存。
{
  "type": "MEMORY_FREE",
  "function_call": "string" /* e.g., "free" */,
  "freed_variable": "string" /* e.g., "ptr", "data" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.9. RESOURCE_ACQUIRE (资源获取)
描述: 获取需要显式释放的系统资源（文件、套接字等）。
{
  "type": "RESOURCE_ACQUIRE",
  "function_call": "string" /* e.g., "fopen", "open", "CreateFile", "socket", "accept", "freopen" */,
  "assigned_to_variable": "string" /* e.g., "pFile", "listen_socket", "data" (for open) */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.10. RESOURCE_RELEASE (资源释放)
描述: 释放系统资源。
{
  "type": "RESOURCE_RELEASE",
  "function_call": "string" /* e.g., "fclose", "close", "CloseHandle", "closesocket", "_close" */,
  "released_variable": "string" /* e.g., "pFile", "listen_socket", "data" (for open handle) */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

### 4.11. COMMAND_EXECUTION (命令执行)
描述: 执行外部命令。
{
  "type": "COMMAND_EXECUTION",
  "function_call": "string" /* e.g., "system", "execlp", "spawnl" */,
  "command_variable": "string" /* 包含命令的变量, e.g., "data" */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
  // uses_tainted_data 由 enricher 动态添加
}

### 4.12. ASSIGNMENT (赋值)
描述: 简单的变量赋值，对跟踪状态（如 NULL 指针）有用。
{
  "type": "ASSIGNMENT",
  "destination_variable": "string" /* e.g., "data", "ptr" */,
  "source_variable_or_value": "string | number | null" /* e.g., "data_buf", "NULL", 0, -1 */,
  "line_number": "integer" /* The function declaration is on the first line, i.e., line_number: 1 */
}

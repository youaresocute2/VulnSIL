# -----------------------------------------------------------------
# [核心] 高质量的 Few-Shot 示例 V1.2
# -----------------------------------------------------------------
FEW_SHOT_EXAMPLES = """
[EXAMPLE 1: VULNERABLE (CWE121)]
[CODE]
CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_loop_19_bad()\n{\n    char * data;\n    char * data_badbuf = (char *)ALLOCA(50*sizeof(char));\n    char * data_goodbuf = (char *)ALLOCA(100*sizeof(char));\n    /* FLAW: Set a pointer to a \"small\" buffer. This buffer will be used in the sinks as a destination\n     * buffer in various memory copying functions using a \"large\" source buffer. */\n    data = data_badbuf;\n    data[0] = '\\0'; /* null terminate */\n    {\n        size_t i;\n        char src[100];\n        memset(src, 'C', 100-1); /* fill with 'C's */\n        src[100-1] = '\\0'; /* null terminate */\n        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of src */\n        for (i = 0; i < 100; i++)\n        {\n            data[i] = src[i];\n        }\n        data[100-1] = '\\0'; /* Ensure the destination buffer is null terminated */\n        printLine(data);\n    }\n    return;\n    /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */\n    /* FIX: Set a pointer to a \"large\" buffer, thus avoiding buffer overflows in the sinks. */\n    data = data_goodbuf;\n    data[0] = '\\0'; /* null terminate */\n    {\n        size_t i;\n        char src[100];\n        memset(src, 'C', 100-1); /* fill with 'C's */\n        src[100-1] = '\\0'; /* null terminate */\n        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of src */\n        for (i = 0; i < 100; i++)\n        {\n            data[i] = src[i];\n        }\n        data[100-1] = '\\0'; /* Ensure the destination buffer is null terminated */\n        printLine(data);\n    }\n}
[/CODE]
[SIL]
```json
{
  "function_name": "CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_loop_19_bad",
  "return_type": "void",
  "parameters": [],
  "variables": [
    {
      "name": "data",
      "type": "char*",
      "size_bytes": "UNKNOWN"
    },
    {
      "name": "data_badbuf",
      "type": "char*",
      "size_bytes": "UNKNOWN"
    },
    {
      "name": "data_goodbuf",
      "type": "char*",
      "size_bytes": "UNKNOWN"
    },
    {
      "name": "i",
      "type": "size_t",
      "size_bytes": "UNKNOWN"
    },
    {
      "name": "src",
      "type": "char[100]",
      "size_bytes": 100
    }
  ],
  "operations": [
    {
      "type": "MEMORY_ALLOC",
      "function_call": "ALLOCA",
      "size_variable_or_value": "50*sizeof(char)",
      "assigned_to_variable": "data_badbuf",
      "line_number": 4
    },
    {
      "type": "MEMORY_ALLOC",
      "function_call": "ALLOCA",
      "size_variable_or_value": "100*sizeof(char)",
      "assigned_to_variable": "data_goodbuf",
      "line_number": 5
    },
    {
      "type": "ASSIGNMENT",
      "destination_variable": "data",
      "source_variable_or_value": "data_badbuf",
      "line_number": 8
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": "data",
      "operation_expression": "data[0] = '\\0'",
      "line_number": 9
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "memset",
      "destination_variable": "src",
      "source_variable": null,
      "size_bytes_written": "100-1",
      "line_number": 13
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": "src",
      "operation_expression": "src[100-1] = '\\0'",
      "line_number": 14
    },
    {
      "type": "INTEGER_OPERATION",
      "operation_expression": "for (i = 0; i < 100; i++)",
      "operands_variables": [
        "i"
      ],
      "assigned_to_variable": null,
      "line_number": 16
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": "data",
      "operation_expression": "data[i] = src[i]",
      "line_number": 18
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "printLine",
      "arguments": [
        "data"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 20
    }
  ]
}
[/SIL]

[EXAMPLE 2: VULNERABLE (CWE122)]
[CODE]
CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_02_bad()\n{\n    if(1)\n    {\n        {\n            charvoid * cv_struct = (charvoid *)malloc(sizeof(charvoid));\n            cv_struct->y = SRC_STR;\n            /* Print the initial block pointed to by cv_struct->y */\n            printLine((char *)cv_struct->y);\n            /* FLAW: Use the sizeof(*cv_struct) which will overwrite the pointer y */\n            memcpy(cv_struct->x, SRC_STR, sizeof(*cv_struct));\n            cv_struct->x[(sizeof(cv_struct->x)/sizeof(char))-1] = '\\0'; /* null terminate the string */\n            printLine((char *)cv_struct->x);\n            printLine((char *)cv_struct->y);\n            free(cv_struct);\n        }\n    }\n    else\n    {\n        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */\n        {\n            charvoid * cv_struct = (charvoid *)malloc(sizeof(charvoid));\n            cv_struct->y = SRC_STR;\n            /* Print the initial block pointed to by cv_struct->y */\n            printLine((char *)cv_struct->y);\n            /* FIX: Use the sizeof(cv_struct->x) to avoid overwriting the pointer y */\n            memcpy(cv_struct->x, SRC_STR, sizeof(cv_struct->x));\n            cv_struct->x[(sizeof(cv_struct->x)/sizeof(char))-1] = '\\0'; /* null terminate the string */\n            printLine((char *)cv_struct->x);\n            printLine((char *)cv_struct->y);\n            free(cv_struct);\n        }\n    }\n}
[/CODE]
[SIL]
```json
{
  "function_name": "CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_02_bad",
  "return_type": "void",
  "parameters": [],
  "variables": [],
  "operations": [
    {
      "type": "ASSIGNMENT",
      "destination_variable": "data",
      "source_variable_or_value": "NULL",
      "line_number": 2
    },
    {
      "type": "MEMORY_ALLOC",
      "function_call": "malloc",
      "size_variable_or_value": "50 * sizeof(char)",
      "assigned_to_variable": "data",
      "line_number": 5
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": null,
      "operation_expression": "data[0] = '\\0';",
      "line_number": 7
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "memset",
      "destination_variable": "src",
      "source_variable": null,
      "size_bytes_written": "100-1",
      "line_number": 11
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": null,
      "operation_expression": "src[100-1] = '\\0'; /* null terminate */",
      "line_number": 12
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "memcpy",
      "destination_variable": "data",
      "source_variable": "src",
      "size_bytes_written": "100*sizeof(char)",
      "line_number": 15
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "printLine",
      "arguments": [
        "data"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 16
    },
    {
      "type": "MEMORY_FREE",
      "function_call": "free",
      "freed_variable": "data",
      "line_number": 17
    }
  ]
}
[/SIL]

[EXAMPLE 3: VULNERABLE (CWE134)]
[CODE]
CWE134_Uncontrolled_Format_String__char_listen_socket_snprintf_02_bad()
{
char * data;
char data_buf[100] = "";
data = data_buf;
{
char buf[1024] = "";
/* read from socket into buf, then copy to data using snprintf */
/* ... (socket read code omitted in dataset preview) ... */
_snprintf(data, 100, data);
printLine(data);
}
}
[/CODE]
[SIL]
```json
{
  "function_name": "CWE134_Uncontrolled_Format_String__char_listen_socket_snprintf_02_bad",
  "return_type": "void",
  "parameters": [],
  "variables": [
    {
      "name": "data_buf",
      "type": "char[100]",
      "size_bytes": 100
    },
    {
      "name": "buf",
      "type": "char[1024]",
      "size_bytes": 1024
    }
  ],
  "operations": [
    {
      "type": "POINTER_ARITHMETIC",
      "variable": null,
      "operation_expression": "data = data_buf;",
      "line_number": 3
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "_snprintf",
      "destination_variable": "data",
      "source_variable": "data",
      "size_bytes_written": "100",
      "line_number": 8
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "printLine",
      "arguments": [
        "data"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 9
    }
  ]
}
[/SIL]

[EXAMPLE 4: VULNERABLE (CWE78)]
[CODE]
CWE78_OS_Command_Injection__char_listen_socket_execl_19_bad()
{
char * data;
char data_buf[100] = "";
data = data_buf;
{
/* read from socket into data */
/* ... omitted ... */
/* POTENTIAL FLAW: Execute command without validating input */
execl("/bin/sh", "sh", "-c", data, NULL);
}
}
[/CODE]
[SIL]
```json
{
  "function_name": "CWE78_OS_Command_Injection__char_listen_socket_execl_19_bad",
  "return_type": "void",
  "parameters": [],
  "variables": [
    {
      "name": "data_buf",
      "type": "char[100]",
      "size_bytes": 100
    }
  ],
  "operations": [
    {
      "type": "POINTER_ARITHMETIC",
      "variable": null,
      "operation_expression": "data = data_buf;",
      "line_number": 3
    },
    {
      "type": "EXTERNAL_CALL",
      "function_call": "recv",
      "stores_to_variable": "data",
      "line_number": 6
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "execl",
      "arguments": [
        "\"/bin/sh\"",
        "\"sh\"",
        "\"-c\"",
        "data",
        "NULL"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 9
    }
  ]
}
[/SIL]

[EXAMPLE 5: VULNERABLE (CWE476)]
[CODE]
CWE476_NULL_Pointer_Dereference__char_19_bad()
{
char * data;
/* FLAW: Set data to NULL */
data = NULL;
/* POTENTIAL FLAW: Attempt to use data (NULL dereference) */
printLine(data);
}
[/CODE]
[SIL]
{
  "function_name": "CWE476_NULL_Pointer_Dereference__char_19_bad",
  "return_type": "void",
  "parameters": [],
  "variables": [
    {
      "name": "data",
      "type": "char*",
      "size_bytes": "UNKNOWN"
    }
  ],
  "operations": [
    {
      "type": "ASSIGNMENT",
      "destination_variable": "data",
      "source_variable_or_value": "NULL",
      "line_number": 4
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "printLine",
      "arguments": [
        "data"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 6
    }
  ]
}
[/SIL]

[EXAMPLE 6: SAFE (label=0)]
[CODE]
CWE122_Heap_Based_Buffer_Overflow__c_dest_char_snprintf_67b_goodG2B_sink()
{
char * data = my_struct.a;
{
char src[100];
memset(src, 'C', 100-1); /* fill with 'C's */
src[100-1] = '\0'; /* null terminate */
/* POTENTIAL FLAW: Possible buffer overflow if src is larger than data */
_snprintf(data, 100, "%s", src);
printLine(data);
free(data);
}
}
[/CODE]
[SIL]
```json
{
  "function_name": "CWE122_Heap_Based_Buffer_Overflow__c_dest_char_snprintf_67b_goodG2B_sink",
  "return_type": "void",
  "parameters": [],
  "variables": [
    {
      "name": "data",
      "type": "char*",
      "size_bytes": "UNKNOWN"
    },
    {
      "name": "src",
      "type": "char[100]",
      "size_bytes": 100
    }
  ],
  "operations": [
    {
      "type": "ASSIGNMENT",
      "destination_variable": "data",
      "source_variable_or_value": "my_struct.a",
      "line_number": 2
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "memset",
      "destination_variable": "src",
      "source_variable": null,
      "size_bytes_written": "100-1",
      "line_number": 4
    },
    {
      "type": "POINTER_ARITHMETIC",
      "variable": null,
      "operation_expression": "src[100-1] = '\\0'; /* null terminate */",
      "line_number": 5
    },
    {
      "type": "BUFFER_WRITE",
      "function_call": "_snprintf",
      "destination_variable": "data",
      "source_variable": "%s",
      "size_bytes_written": "100",
      "line_number": 7
    },
    {
      "type": "FUNCTION_CALL",
      "function_call": "printLine",
      "arguments": [
        "data"
      ],
      "is_format_string_sink": false,
      "format_string_arg_index": null,
      "line_number": 8
    },
    {
      "type": "MEMORY_FREE",
      "function_call": "free",
      "freed_variable": "data",
      "line_number": 9
    }
  ]
}
[/SIL]
"""
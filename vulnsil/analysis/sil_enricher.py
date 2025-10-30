# vulnsil/analysis/sil_enricher.py

from typing import Dict, Any, Set

def enrich_sil(sil_data: Dict[str, Any], code: str) -> Dict[str, Any]:
    """
    [非 LLM - V1.2 - 最终版]
    通过轻量级静态分析增强 SIL JSON。

    主要任务：
    1.  污点传播 (Taint Propagation) - 包含迭代处理，处理 ASSIGNMENT。
    """
    print("Running SIL Enrichment (Taint Analysis)...")

    # 初始化空的 enrichment_analysis 字段以保证存在
    sil_data["enrichment_analysis"] = {"tainted_variables": [], "taint_sources": []}

    if "operations" not in sil_data or not sil_data["operations"]:
        print("  -> No operations found in SIL, skipping enrichment.")
        return sil_data

    tainted_variables: Set[str] = set()
    taint_sources_list: Set[str] = set()

    # 2. 查找污点源 (Taint Sources)
    if "parameters" in sil_data:
        for param in sil_data["parameters"]:
            param_name = param.get("name")
            if param_name:
                tainted_variables.add(param_name)

    for op in sil_data["operations"]:
        if op.get("type") == "EXTERNAL_CALL":
            var_name = op.get("stores_to_variable")
            if var_name:
                print(f"  [Taint Source] Variable '{var_name}' is tainted by {op.get('function_call')}")
                tainted_variables.add(var_name)
                taint_sources_list.add(var_name)

    initial_taint_count = len(tainted_variables)
    if initial_taint_count > 0:
        print(f"  Initial tainted variables ({initial_taint_count}): {sorted(list(tainted_variables))}")
    else:
        print("  No initial taint sources found.")
        return sil_data # No sources, no propagation needed

    # 3. 迭代传播污点
    iteration = 0
    max_iterations = 10
    while iteration < max_iterations:
        iteration += 1
        newly_tainted_in_iter = set()

        for op in sil_data["operations"]:
            op_type = op.get("type")

            # 规则 1: ASSIGNMENT (dest = src)
            if op_type == "ASSIGNMENT":
                src = op.get("source_variable_or_value")
                dest = op.get("destination_variable")
                if isinstance(src, str) and src in tainted_variables and dest not in tainted_variables:
                    newly_tainted_in_iter.add(dest)

            # 规则 2: BUFFER_WRITE (memcpy(dest, src, size))
            elif op_type == "BUFFER_WRITE":
                src = op.get("source_variable")
                dest = op.get("destination_variable")
                size = op.get("size_bytes_written")
                propagate_to_dest = False
                if isinstance(src, str) and src in tainted_variables: propagate_to_dest = True
                if isinstance(size, str) and size in tainted_variables: propagate_to_dest = True
                if propagate_to_dest and dest not in tainted_variables:
                    newly_tainted_in_iter.add(dest)

            # 规则 3: INTEGER_OPERATION (size = count * 2; buf[idx])
            elif op_type == "INTEGER_OPERATION":
                 operands = op.get("operands_variables", [])
                 dest = op.get("assigned_to_variable")
                 is_operand_tainted = any(isinstance(op_var, str) and op_var in tainted_variables for op_var in operands)
                 if is_operand_tainted and dest and dest not in tainted_variables:
                     newly_tainted_in_iter.add(dest)

            # 规则 5: FUNCTION_CALL / COMMAND_EXECUTION (标记)
            elif op_type == "FUNCTION_CALL" or op_type == "COMMAND_EXECUTION":
                 args = op.get("arguments", [])
                 cmd_var = op.get("command_variable")
                 check_vars = []
                 if args: check_vars.extend(args)
                 if cmd_var: check_vars.append(cmd_var)
                 is_tainted_argument_present = any(isinstance(var, str) and var in tainted_variables for var in check_vars)
                 if is_tainted_argument_present and not op.get("uses_tainted_data"):
                     op["uses_tainted_data"] = True
                     print(f"  [Iter {iteration} Taint Sink Detected] Tainted data used in call to '{op.get('function_call') or op.get('type')}'")

        if newly_tainted_in_iter:
            new_count = len(newly_tainted_in_iter)
            tainted_variables.update(newly_tainted_in_iter)
            print(f"  Completed iteration {iteration}, found {new_count} new tainted variables: {sorted(list(newly_tainted_in_iter))}")
        else:
            print(f"  Taint analysis reached fixed point after {iteration} iterations.")
            break

    if iteration == max_iterations:
         print(f"  警告：污点分析达到最大迭代次数 ({max_iterations})。结果可能不完整。")

    # 4. 将最终污点信息添加回 SIL
    sil_data["enrichment_analysis"]["tainted_variables"] = sorted(list(tainted_variables))
    sil_data["enrichment_analysis"]["taint_sources"] = sorted(list(taint_sources_list))
    final_taint_count = len(tainted_variables)
    print(f"Enrichment complete. Total tainted variables ({final_taint_count}): {sil_data['enrichment_analysis']['tainted_variables']}")

    return sil_data
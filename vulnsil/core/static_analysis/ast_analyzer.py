# vulnsil/core/static_analysis/ast_analyzer.py
import logging
import threading
import re
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class ASTHeuristicAnalyzer:
    """
    多级静态分析器 (Tree-sitter AST + Regex Fallback)
    [Thread-Safe Edition]: Added locks to protect shared Parser instance.
    [改进] 用Tree-sitter计算简单图特征（节点数/最大深度）
    """

    def __init__(self):
        # --- 1. 定义高危函数列表 (保持不变) ---
        self.DANGEROUS_FUNCS = {
            # --- 1. Memory Safety & Buffers (Classic) ---
            'memcpy', 'memmove', 'memset', 'memcmp', 'bcopy', 'memccpy',
            'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen',
            'stpcpy', 'stpncpy', 'wcscpy', 'wcsncpy', 'wcscat', 'wcsncat',
            'sprintf', 'vsprintf', 'swprintf', 'vswprintf', 'snprintf', 'vsnprintf', 'vasprintf',
            'bzero', 'explicit_bzero',

            # --- 2. Heap Management (Extended for Kernel) ---
            'malloc', 'calloc', 'realloc', 'alloca', 'free',
            'valloc', 'pvalloc', 'aligned_alloc',
            'strdup', 'strndup', 'memdup', 'wcsdup',
            'av_malloc', 'av_realloc', 'av_free', 'g_malloc', 'g_malloc0', 'g_free',
            # Linux Generic
            'kmalloc', 'kzalloc', 'kfree', 'vmalloc', 'kvfree', 'devm_kzalloc',
            # Linux Slab/SKB (New!)
            'kmem_cache_alloc', 'kmem_cache_zalloc', 'kmem_cache_free', 'kmemdup',
            'kfree_skb', 'dev_kfree_skb', 'consume_skb',

            # --- 3. Numeric & ID ---
            'atoi', 'atol', 'atoll', 'atof',
            'strtol', 'strtoul', 'strtoll', 'strtoull',
            'strtod', 'strtof', 'strtold',
            'strtoimax', 'strtoumax',
            'simple_strtoul', 'simple_strtol',
            'idr_find', 'idr_remove',  # Kernel ID management

            # --- 4. Input Validation & Injection ---
            'gets', 'gets_s', 'scanf', 'fscanf', 'sscanf',
            'vscanf', 'vfscanf', 'vsscanf',
            'system', 'popen', 'pclose',
            'exec', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe',
            'WinExec', 'ShellExecute', 'CreateProcess', 'CreateProcessAsUser',
        }

        # --- Tree-sitter 初始化 ---
        try:
            self.LANG_C = Language(tree_sitter_c.language())
            self.parser = Parser(self.LANG_C)  # [改进] 使用使用线程局部Parser
            self.query_call = self.LANG_C.query("(call_expression function: (identifier) @func)")
        except Exception as e:
            logger.warning(f"AST Engine Init skipped: {e}. Running in Regex-Only Mode.")
            self.parser = None

        # 正则Fallback
        self.regex_patterns = {api: re.compile(rf'\b{re.escape(api)}\b') for api in self.DANGEROUS_FUNCS}

        # 线程锁
        self._lock = threading.Lock()

    def scan(self, code: str):
        """
        扫描代码，提取高危API和图特征
        返回：(has_dangerous, apis, graph_density)
        [改进] graph_density = max_depth / node_count (简单度量)
        """
        found_apis = set()

        # 1. 优先 AST (Thread-Safe Block)
        if self.parser and self.query_call:
            try:
                # [关键修改]: 加锁保护解析过程
                with self._lock:
                    tree = self.parser.parse(code.encode('utf-8', errors='ignore'))

                if hasattr(self.query_call, 'captures'):
                    for cap in self.query_call.captures(tree.root_node):
                        node = cap[0] if isinstance(cap, tuple) else cap
                        name = code[node.start_byte:node.end_byte].strip()
                        if name in self.DANGEROUS_FUNCS:
                            found_apis.add(name)

                elif hasattr(self.query_call, 'matches'):
                    for _, match in self.query_call.matches(tree.root_node):
                        nodes = match.values() if isinstance(match, dict) else match
                        n_list = nodes if isinstance(nodes, list) else [nodes]
                        for node in n_list:
                            if isinstance(node, list):
                                for sub in node:
                                    name = code[sub.start_byte:sub.end_byte].strip()
                                    if name in self.DANGEROUS_FUNCS: found_apis.add(name)
                            else:
                                name = code[node.start_byte:node.end_byte].strip()
                                if name in self.DANGEROUS_FUNCS: found_apis.add(name)
            except Exception:
                pass

        # 2. 正则 Fallback (Regex 是线程安全的)
        if not found_apis:
            for api, pattern in self.regex_patterns.items():
                if pattern.search(code):
                    found_apis.add(api)

        has_dangerous = len(found_apis) > 0

        # 3. 新增：Tree-sitter图特征（节点数 + 最大深度）
        graph_density = 0.0
        if self.parser:
            try:
                tree = self.parser.parse(code.encode('utf-8', errors='ignore'))
                node_count = 0
                max_depth = 0

                def traverse(node, depth=0):
                    nonlocal node_count, max_depth
                    node_count += 1
                    max_depth = max(max_depth, depth)
                    for child in node.children:
                        traverse(child, depth + 1)

                traverse(tree.root_node)
                if node_count > 0:
                    graph_density = max_depth / node_count  # 简单密度度量
            except:
                pass

        return has_dangerous, list(found_apis), graph_density
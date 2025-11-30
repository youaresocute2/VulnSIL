# vulnsil/core/static_analysis/ast_analyzer.py
import logging
import threading
import re
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class ASTHeuristicAnalyzer:
    """
    AST + Regex Keyword Analyzer.
    Thread-safe implementation for identifying dangerous APIs.
    """

    def __init__(self):
        # Definition of Dangerous Functions
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
            'dlopen', 'dlsym', 'LoadLibrary', 'GetProcAddress',

            # --- 5. File/Path/IO ---
            'open', 'fopen', 'freopen', 'openat', 'fdopen',
            'read', 'fread', 'pread', 'write', 'fwrite', 'pwrite',
            'unlink', 'remove', 'rename', 'mkdir', 'rmdir', 'chdir',
            'realpath', 'getcwd', 'access', 'chmod', 'chown',
            'tmpfile', 'tmpnam', 'mkstemp', 'mktemp',

            # --- 6. Kernel Data Copy & Macros (Must include underscores) ---
            'copy_from_user', 'copy_to_user', '_copy_from_user', '_copy_to_user',
            '__copy_from_user', '__copy_to_user',  # (New! Double underscore)
            'get_user', 'put_user', '__get_user', '__put_user',
            'sock_recvmsg', 'sock_sendmsg',

            # --- 7. Kernel Subsystems (Block / Net / Concurrency) ---
            # Concurrency & Locking (New!)
            'atomic_read', 'atomic_set', 'atomic_inc', 'atomic_dec',
            'spin_lock', 'spin_unlock', 'mutex_lock', 'mutex_unlock',
            # Networking Queues (New!)
            'skb_dequeue', 'skb_queue_tail', 'skb_queue_head', 'skb_peek', 'skb_unlink',
            # Block Device / IO (New!)
            'blk_execute_rq', '__blk_send_generic', 'blk_execute_rq_nowait',
            'sg_io', 'bsg_read', 'bsg_write',

            # --- 8. X11 / Xorg ---
            'dixLookupDevice', 'dixLookup', 'AttachDevice', 'RemoveDevice', 'GetMaster',

            # --- 9. Crypto & Misc ---
            'MD4', 'MD5', 'SHA1', 'crypt', 'rand', 'srand', 'getenv', 'setenv', 'putenv',
            'rc4_hmac_md5', 'EVP_EncryptInit'
        }

        self.regex_patterns = {
            api: re.compile(r'\b' + re.escape(api) + r'\b')
            for api in self.DANGEROUS_FUNCS
        }

        self._lock = threading.Lock()
        self.parser = None
        self.query_call = None

        try:
            self.LANG_C = Language(tree_sitter_c.language())
            self.parser = Parser(self.LANG_C)
            self.query_call = self.LANG_C.query("""(call_expression function: (identifier) @func_name)""")
        except Exception as e:
            logger.warning(f"AST Parser Init warning: {e}. Fallback to Regex-only.")

    def scan(self, code: str):
        """
        Scans code for dangerous APIs using AST first, then Regex fallback.
        """
        found_apis = set()

        # 1. AST Scan (Thread-Safe Block)
        if self.parser and self.query_call:
            try:
                with self._lock:
                    tree = self.parser.parse(code.encode('utf-8', errors='ignore'))

                # Using query matches logic
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
                        for n in n_list:
                            name = code[n.start_byte:n.end_byte].strip()
                            if name in self.DANGEROUS_FUNCS:
                                found_apis.add(name)
            except Exception:
                pass

        # 2. Regex Fallback
        if not found_apis:
            for api, pattern in self.regex_patterns.items():
                if pattern.search(code):
                    found_apis.add(api)

        return (len(found_apis) > 0), list(found_apis)


class ASTGraphAnalyzer:
    """
    [New Engine] Topological Metric Calculator.
    Computes graph density derived from Abstract Syntax Tree.
    Density = max_depth / node_count.
    This serves as a structural complexity feature, orthogonal to API count.
    """

    def __init__(self):
        self._local = threading.local()
        try:
            self.LANG = Language(tree_sitter_c.language())
        except Exception as e:
            logger.error(f"Graph Analyzer Init Failed: {e}")
            self.LANG = None

    def _get_parser(self):
        """Thread-local parser instantiation"""
        if not hasattr(self._local, 'parser'):
            if self.LANG:
                self._local.parser = Parser(self.LANG)
            else:
                self._local.parser = None
        return self._local.parser

    def analyze_graph_metrics(self, code: str):
        """
        Calculate:
        - Node Count
        - Max Depth
        - Density
        """
        parser = self._get_parser()
        if not parser:
            return {"ast_node_count": 0, "ast_max_depth": 0, "ast_graph_density": 0.0}

        try:
            tree = parser.parse(code.encode('utf-8', errors='ignore'))
            root = tree.root_node

            # DFS Traversal to find depth and count
            # Stack stores (node, depth)
            stack = [(root, 1)]

            max_depth = 0
            node_count = 0

            while stack:
                node, depth = stack.pop()
                node_count += 1

                if depth > max_depth:
                    max_depth = depth

                # Push children to stack
                # Iterating usually gives direct children
                for child in node.children:
                    stack.append((child, depth + 1))

            # Definition: High density = Deep logic relative to size.
            # Low density = Flat lists of instructions.
            density = 0.0
            if node_count > 0:
                density = float(max_depth) / float(node_count)

            return {
                "ast_node_count": node_count,
                "ast_max_depth": max_depth,
                "ast_graph_density": density
            }

        except Exception as e:
            logger.warning(f"Graph metric calc failed: {e}")
            return {
                "ast_node_count": 0,
                "ast_max_depth": 0,
                "ast_graph_density": 0.0
            }
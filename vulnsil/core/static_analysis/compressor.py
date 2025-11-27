# vulnsil/core/static_analysis/compressor.py
import logging
import threading
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class SemanticCompressor:
    """
    语义压缩器
    [Thread-Safe Edition v2]: Replaced Lock with ThreadLocal for true concurrency.
    """

    def __init__(self):
        try:
            # Language 对象是线程安全的，可以全局共享
            self.LANG_C = Language(tree_sitter_c.language())
            # 预编译查询也是线程安全的
            self.query_comment = self.LANG_C.query("(comment) @comment")
        except Exception as e:
            raise RuntimeError(f"Tree-sitter Init Failed: {e}")

        self.FOLD_TYPES = {'compound_statement', 'while_statement', 'for_statement', 'if_statement'}

        # 必须包含所有高危 API
        self.CRITICAL_KEYWORDS = [
            # --- 1. Control Flow ---
            b'return', b'goto', b'break', b'continue', b'throw', b'catch', b'try',
            b'asm', b'__asm', b'#include', b'#define',

            # --- 2. Classic Memory ---
            b'memcpy', b'memmove', b'memset', b'malloc', b'calloc', b'realloc', b'free',
            b'alloca', b'bcopy', b'strdup',

            # --- 3. Strings & Output ---
            b'strcpy', b'strncpy', b'strcat', b'strncat', b'sprintf', b'snprintf',
            b'vsprintf', b'vsnprintf', b'gets', b'scanf', b'sscanf',

            # --- 4. Numeric / Integer Overflow Sources (DiverseVul Update) ---
            b'atoi', b'atol', b'strtol', b'strtoul', b'strtoull', b'simple_strtoul',

            # --- 5. System/Process/Injection ---
            b'system', b'exec', b'popen', b'dlopen', b'LoadLibrary',
            b'fork', b'clone', b'setuid', b'setgid',

            # --- 6. IO & Kernel Sinks ---
            b'open', b'fopen', b'read', b'write', b'recv', b'send',
            b'remove', b'unlink', b'rename',
            b'copy_from_user', b'copy_to_user', 'get_user', 'put_user',  # Kernel User Copy
            b'printk', b'pr_info', b'pr_err', 'dev_info', 'netdev_err',  # Kernel Logging
            # --- 7. Race / Sync (CWE-362) ---
            b'mutex_lock', b'mutex_unlock', b'spin_lock', b'spin_unlock',
            b'sem_wait', b'sem_post', b'pthread_mutex_lock', b'pthread_mutex_unlock',

            # --- 8. Null / Pointer (CWE-476) ---
            b'NULL', b'nullptr', b'deref', b'->', b'*',  # Basic Deref
            b'check_null', 'IS_ERR', 'PTR_ERR',  # Kernel Specific

            # --- 9. Format String (CWE-134) ---
            b'printf', b'fprintf', b'vprintf', b'vfprintf', b'scanf', b'fscanf',

            # --- 10. Project-Specific (DiverseVul Coverage) ---
            b'skb_put', b'skb_push', b'skb_trim', b'skb_reserve',  # Linux Net/SKB
            b'vma_alloc', b'vma_free', b'mm_alloc', b'mm_free',  # Memory Management
            b'pci_alloc', b'pci_free', b'usb_alloc', b'usb_free',  # Drivers
            b'crypto_alloc', b'crypto_free',  # Crypto

            # --- 11. Concurrency (Extended) ---
            b'atomic_inc', b'atomic_dec', b'rcu_read_lock', b'rcu_read_unlock',
            b'wait_queue', b'complete', b'wait_for_completion',

            # --- 12. File / Path (CWE-22) ---
            b'realpath', b'canonicalize_path', b'mkpath', b'mkdir', b'rmdir',
            b'chdir', b'getcwd', b'access', b'stat', b'lstat'
        ]

        # Thread Local Parser (线程本地，避免锁)
        self.local = threading.local()

    def _get_parser(self):
        if not hasattr(self.local, 'parser'):
            self.local.parser = Parser(self.LANG_C)
        return self.local.parser

    def _get_captures(self, query, root_node):
        """辅助函数: 获取查询捕获 (兼容 matches/captures)"""
        res = []
        try:
            if hasattr(query, 'captures'):
                res = query.captures(root_node)
            elif hasattr(query, 'matches'):
                for _, match in query.matches(root_node):
                    for item in match:
                        if isinstance(item, list):
                            for i in item:
                                res.append((i, "comment"))
                        else:
                            res.append((item, "comment"))
        except:
            pass
        return res

    def compress(self, code: str, limit: int = 14000) -> str:
        if len(code) < limit:
            return code

        code_bytes = code.encode('utf-8')

        # [核心修改] 不再需要锁，直接获取线程局部 Parser
        parser = self._get_parser()

        try:
            tree = parser.parse(code_bytes)
        except:
            return code[:limit]

        ranges_to_hide = []

        captures = self._get_captures(self.query_comment, tree.root_node)
        for item in captures:
            node = item[0] if isinstance(item, tuple) else item
            ranges_to_hide.append((node.start_byte, node.end_byte, b" "))

        def visit(node):
            length = node.end_byte - node.start_byte
            if node.type in self.FOLD_TYPES and length > 400:
                node_text = code_bytes[node.start_byte:node.end_byte]
                has_critical = any(kw in node_text for kw in self.CRITICAL_KEYWORDS)
                if not has_critical:
                    placeholder = b" /* ... Logic Folded ... */ "
                    ranges_to_hide.append((node.start_byte + 1, node.end_byte - 1, placeholder))
                    return

            for child in node.children:
                visit(child)

        visit(tree.root_node)

        ranges_to_hide.sort(key=lambda x: x[0], reverse=True)

        mod_code = bytearray(code_bytes)
        for start, end, replacement in ranges_to_hide:
            mod_code[start:end] = replacement

        compressed = mod_code.decode('utf-8', errors='ignore')

        if len(compressed) > limit:
            half = limit // 2
            compressed = compressed[:half] + "\n/* ... TRUNCATED ... */\n" + compressed[-half:]

        return compressed
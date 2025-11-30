# vulnsil/core/static_analysis/compressor.py
import logging
import threading
from tree_sitter import Language, Parser
import tree_sitter_c

logger = logging.getLogger(__name__)


class SemanticCompressor:
    """
    AST-based Code Compressor.
    Function: Removes comments and collapses large utility loops/blocks not critical for flow analysis.

    [Enhanced]: Thread-safety via thread-local storage.
    [Enhanced]: Iterative traversal to prevent RecursionError on deep ASTs.
    """

    def __init__(self):
        try:
            # Language def is immutable/safe to share
            self.LANG_C = Language(tree_sitter_c.language())

            # Query strings are safe, but Query objects should be re-used carefully.
            # Simple query strings stored here.
            self.query_str_comment = "(comment) @comment"

        except Exception as e:
            raise RuntimeError(f"Tree-sitter Init Failed: {e}")

        # Node types eligible for folding if they contain no sensitive keywords
        self.FOLD_TYPES = {
            'compound_statement', 'while_statement', 'for_statement',
            'if_statement', 'switch_statement'
        }

        # [Preservation List] Keywords that imply Security Logic (Control Flow + Memory + Sinks)
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
            b'copy_from_user', b'copy_to_user', b'get_user', b'put_user',

            # --- 7. X11 / Xorg ---
            b'dixLookupDevice', b'AttachDevice', b'RemoveDevice',

            # --- 8. Important Logic ---
            b'if', b'else', b'switch', b'for', b'while', b'do',
            b'assert', b'likely', b'unlikely',

            # --- 9. Crypto ---
            b'MD5', b'SHA1', b'crypt', b'password', b'key', b'secret'
        ]

        # [Fix VI] Thread Safety
        # Parsers are stateful and not thread-safe. Store one per thread.
        self._local = threading.local()

    def _get_parser(self):
        """Lazy init parser for the current thread"""
        if not hasattr(self._local, 'parser'):
            p = Parser(self.LANG_C)
            self._local.parser = p
            # Query object is compiled per parser/thread context often safer
            self._local.q_comment = self.LANG_C.query(self.query_str_comment)
        return self._local.parser, self._local.q_comment

    def compress(self, code: str, limit: int = 12000) -> str:
        """
        Compresses C code by removing comments and folding non-critical heavy blocks.
        """
        if not code or len(code) <= limit:
            return code

        # 1. Parse (Thread-safe acquisition)
        code_bytes = code.encode('utf-8', 'replace')
        parser, q_comment = self._get_parser()

        try:
            tree = parser.parse(code_bytes)
        except Exception as e:
            # Fallback on parse failure
            return code[:limit]

        ranges_to_hide = []

        # 2. Identify Comments
        # Using query matches/captures
        if hasattr(q_comment, 'captures'):
            # 旧版 API / 部分新版 API
            for match in q_comment.captures(tree.root_node):
                # capture tuple (node, type) or just node
                node = match[0] if isinstance(match, tuple) else match
                ranges_to_hide.append((node.start_byte, node.end_byte, b" "))
        elif hasattr(q_comment, 'matches'):
            # 新版 API
            for _, match in q_comment.matches(tree.root_node):
                # match 可能是 dict {name: node/list} 或 list
                nodes = match.values() if isinstance(match, dict) else match
                # 确保它是列表以便迭代
                if not isinstance(nodes, (list, tuple)):
                    nodes = [nodes]

                for n_item in nodes:
                    # 某些版本可能是 list of nodes
                    sub_nodes = n_item if isinstance(n_item, list) else [n_item]
                    for n in sub_nodes:
                        ranges_to_hide.append((n.start_byte, n.end_byte, b" "))

        # 3. Identify Low-Risk Logic Blocks [Fix VI: Iterative Stack]
        # Switched from Recursion to Stack Iteration to handle deep ASTs safely
        stack = [tree.root_node]

        while stack:
            node = stack.pop()
            # If stack order is important for "logic" folding (parent vs child), iteration suffices
            # since ranges are applied by byte offset later.

            # Check foldability
            if node.type in self.FOLD_TYPES:
                length = node.end_byte - node.start_byte
                # Fold heuristic
                if length > 400:
                    node_text = code_bytes[node.start_byte:node.end_byte]

                    has_critical = any(kw in node_text for kw in self.CRITICAL_KEYWORDS)

                    if not has_critical:
                        placeholder = b" /* ... Logic Folded ... */ "
                        ranges_to_hide.append((node.start_byte + 1, node.end_byte - 1, placeholder))
                        # If folded, do NOT push children to stack (prune branch)
                        continue

                        # Push children
            # Reverse order push preserves general left-to-right order (Preorder) in pop
            if node.children:
                stack.extend(reversed(node.children))

        # 4. Apply Changes
        # Sort ranges reverse to modify buffer safely
        ranges_to_hide.sort(key=lambda x: x[0], reverse=True)

        mod_code = bytearray(code_bytes)
        for start, end, replacement in ranges_to_hide:
            if start < end:
                mod_code[start:end] = replacement

        compressed_str = mod_code.decode('utf-8', errors='ignore')

        # 5. Final Hard Cap Check
        # If semantically compressed code is still too long, do simple truncate
        if len(compressed_str) > limit:
            MAX_HARD_LIMIT = limit + 500  # Allowance for comments

            # [Fix 7] Absolute safety cap
            if len(compressed_str) > MAX_HARD_LIMIT:
                logger.warning(f"Compressor output still massive ({len(compressed_str)} > {limit}). Truncating hard.")
                half = limit // 2
                compressed_str = compressed_str[:half] + "\n/* ... FORCE TRUNCATED ... */\n" + compressed_str[-half:]
            else:
                # Soft overage behavior (Original logic maintained for small overages)
                half = limit // 2
                compressed_str = compressed_str[:half] + "\n/* ... TRUNCATED ... */\n" + compressed_str[-half:]

        return compressed_str
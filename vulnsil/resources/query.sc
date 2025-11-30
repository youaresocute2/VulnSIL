import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import java.io.{File, PrintWriter}

// 定义输出路径
val outFile = raw"{{OUT_FILE}}"

try {
  // 1. 加载 CPG
  val cpgOpt = importCpg(raw"{{CPG_FILE}}")

  if (cpgOpt.isEmpty) {
     val writer = new PrintWriter(new File(outFile))
     try {
       // [修复] 显式构造 ujson 对象
       val errJson = ujson.Obj("error" -> "CPG Import Failed")
       val jsonArr = ujson.Arr(errJson)

       val jsonStr = ujson.write(jsonArr, 2, false, false)
       writer.write(jsonStr)
     } finally {
       writer.close()
     }
  } else {
      val cpg = cpgOpt.get
      try {
          val dangerousSinksNames = Set(
            // --- [1] Memory Safety (Classic CWE-120, 787) ---
            "memcpy", "memmove", "memset", "memcmp", "bcopy", "memccpy",
            "strcpy", "strncpy", "strcat", "strncat", "strlen",
            "sprintf", "vsprintf", "snprintf", "swprintf",
            "vsnprintf", "vasprintf", "vsscanf", "vfscanf",
            "stpcpy", "stpncpy", "wcscpy", "wcsncpy", "wcscat", "wcsncat", // Wide Char
            "bzero", "explicit_bzero", // Kernel/BSD specific

            // --- [2] Input Validation (CWE-20) ---
            "gets", "gets_s", "scanf", "fscanf", "sscanf", "vscanf",

            // --- [3] Heap Management (CWE-416, 400) ---
            "malloc", "calloc", "realloc", "alloca", "free",
            "valloc", "pvalloc", "aligned_alloc",
            "strdup", "strndup", "memdup", "wcsdup", // Implicit alloc

            // Project Specific Allocators (DiverseVul Coverage)
            "av_malloc", "av_realloc", "av_free",         // FFmpeg
            "g_malloc", "g_malloc0", "g_free",            // GLib/QEMU
            "kmalloc", "kzalloc", "kfree", "vmalloc", "kvfree", "devm_kzalloc", // Linux Generic

            // Linux Kernel Advanced Memory (Slab & SKB)
            "kmem_cache_alloc", "kmem_cache_zalloc", "kmem_cache_free", "kmemdup",
            "kfree_skb", "dev_kfree_skb", "consume_skb",

            // --- [4] Numeric & Integer Overflow Sources (CWE-190) ---
            "atoi", "atol", "atoll", "atof",
            "strtol", "strtoul", "strtoll", "strtoull",
            "strtod", "strtof", "strtold",
            "strtoimax", "strtoumax",
            "simple_strtoul", "simple_strtol", // Kernel Utils

            // --- [5] Command/Code Injection (CWE-78, 77) ---
            "system", "popen", "pclose",
            "exec", "execl", "execlp", "execle", "execv", "execvp", "execvpe",
            "WinExec", "ShellExecute", "CreateProcess", "CreateProcessAsUser",
            "dlopen", "dlsym", "LoadLibrary", "GetProcAddress",

            // --- [6] File/Path/IO (CWE-22, TOC/TOU) ---
            "open", "fopen", "freopen", "openat", "fdopen",
            "read", "fread", "pread", "write", "fwrite", "pwrite",
            "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
            "sock_recvmsg", "sock_sendmsg",
            "unlink", "remove", "rename", "mkdir", "rmdir", "chdir",
            "access", "chmod", "chown", "getcwd", "realpath",
            "tmpfile", "tmpnam", "mkstemp", "mktemp",

            // --- [7] Linux Kernel Specific Data Transfer (CRITICAL) ---
            // Missing these results in FN for ID 121 etc.
            "copy_from_user", "copy_to_user",
            "_copy_from_user", "_copy_to_user",
            "__copy_from_user", "__copy_to_user",
            "get_user", "put_user",
            "__get_user", "__put_user",

            // --- [8] Concurrency & Driver Logic (CWE-362) ---
            "atomic_read", "atomic_set", "atomic_inc", "atomic_dec",
            "spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock",
            "skb_dequeue", "skb_queue_tail", "skb_queue_head", "skb_peek", "skb_unlink",
            "blk_execute_rq", "__blk_send_generic", "blk_execute_rq_nowait",
            "sg_io", "bsg_read", "bsg_write",

            // --- [9] X11 / Xorg / Graphics Specific ---
            "dixLookup", "dixLookupDevice", "AttachDevice", "RemoveDevice", "GetMaster",

            // --- [10] Crypto & Misc & Environment ---
            "MD4", "MD5", "SHA1", "crypt", "rand", "srand",
            "getenv", "setenv", "putenv"
          )

          implicit val context: EngineContext = EngineContext()

          val results = cpg.method.internal.filter(_.filename.endsWith(".c")).map { method =>

              val currentFilename = method.filename

              // API Check
              val usedApis = method.ast.isCall.name.filter(n =>
                  dangerousSinksNames.exists(d => n.contains(d))
              ).l.distinct

              // Complexity
              val complexity = method.controlStructure.size

              // Data Flow
              val sources = method.parameter.l
              val sinks = method.ast.isCall.filter(c =>
                  dangerousSinksNames.exists(d => c.name.contains(d))
              ).argument.l

              var hasFlow = false
              if (sinks.nonEmpty && sources.nonEmpty) {
                  if (sinks.exists(s => s.reachableBy(sources).nonEmpty)) {
                      hasFlow = true
                  }
              }

              // [核心修复]
              // 1. 将 List[String] 显式转换为 ujson.Arr
              val apisJson = ujson.Arr.from(usedApis)

              // 2. 返回明确类型的 ujson.Obj，而不是 Scala Map
              ujson.Obj(
                  "filename" -> currentFilename,
                  "success" -> true, // implicitly ujson.Bool
                  "apis" -> apisJson,
                  "complexity" -> complexity, // implicitly ujson.Num
                  "has_data_flow" -> hasFlow  // implicitly ujson.Bool
              )
          }.l

          val writer = new PrintWriter(new File(outFile))
          try {
             // [核心修复] 3. 将 List[ujson.Obj] 转换为 ujson.Arr，这才是 ujson.Value 类型
             val finalJson = ujson.Arr.from(results)

             // 显式参数 write
             val jsonStr = ujson.write(finalJson, 2, false, false)
             writer.write(jsonStr)
          } finally {
             writer.close()
          }

      } catch {
        case e: Exception =>
          val writer = new PrintWriter(new File(outFile))
          try {
             // 错误输出也要构造 Obj -> Arr
             val err = ujson.Obj("success" -> false, "error" -> e.toString)
             val jsonArr = ujson.Arr(err)
             val jsonStr = ujson.write(jsonArr, 2, false, false)
             writer.write(jsonStr)
          } finally {
             writer.close()
          }
      } finally {
          cpg.close()
      }
  }
} catch {
    case e: Exception =>
        println("FATAL SCALA SCRIPT ERROR: " + e.toString)
}
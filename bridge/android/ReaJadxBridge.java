import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.ResourceFile;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.input.data.ICodeReader;
import jadx.api.plugins.input.data.IMethodRef;
import jadx.api.plugins.input.insns.InsnIndexType;
import jadx.api.plugins.input.insns.Opcode;
import jadx.api.plugins.loader.JadxBasePluginLoader;
import jadx.api.plugins.loader.JadxPluginLoader;
import jadx.core.Jadx;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.FieldNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.xmlgen.ResContainer;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * REA-owned stdio bridge over the unmodified upstream JADX release JAR
 * (github.com/skylot/jadx). It uses only the jadx.api / jadx.core classes of
 * that JAR plus the JDK, and speaks a minimal newline-delimited JSON-RPC 2.0
 * subset of the MCP stdio protocol (initialize, ping, tools/list, tools/call)
 * that REA's TypeScript adapter drives. Every reply is one UTF-8 line.
 */
class ReaJadxBridge {
  static final String NAME = "rea-jadx-bridge";
  static final String VERSION = "2";
  static final int DEFAULT_MAX_SOURCE_BYTES = 1024 * 1024;
  static final long DECOMPILE_TIMEOUT_MS = 90_000L;
  static final int DECOMPILED_CLASS_CACHE = 64;
  static final String FALLBACK_PROTOCOL_VERSION = "2025-06-18";
  /** Upstream input/metadata plugins this bridge admits; all others in the JAR stay unloaded. */
  static final Set<String> ADMITTED_PLUGINS = Set.of(
      "jadx.plugins.input.dex.DexInputPlugin",
      "jadx.plugins.input.java.JavaInputPlugin",
      "jadx.plugins.input.javaconvert.JavaConvertPlugin",
      "jadx.plugins.input.smali.SmaliInputPlugin",
      "jadx.plugins.input.xapk.XApkInputPlugin",
      "jadx.plugins.kotlin.metadata.KotlinMetadataPlugin");

  // ── Minimal JSON (RFC 8259) without third-party libraries ─────────────────

  static final class Json {
    private final String text;
    private int pos;

    private Json(String text) { this.text = text; }

    static Object parse(String text) {
      Json parser = new Json(text);
      parser.space();
      Object value = parser.value(0);
      parser.space();
      if (parser.pos != text.length()) throw parser.error("trailing characters");
      return value;
    }

    private IllegalArgumentException error(String reason) {
      return new IllegalArgumentException("Malformed JSON at " + pos + ": " + reason);
    }

    private void space() {
      while (pos < text.length()) {
        char c = text.charAt(pos);
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
        pos++;
      }
    }

    private Object value(int depth) {
      if (depth > 256) throw error("nesting too deep");
      if (pos >= text.length()) throw error("unexpected end");
      char c = text.charAt(pos);
      switch (c) {
        case '{': return object(depth);
        case '[': return array(depth);
        case '"': return string();
        case 't': return literal("true", Boolean.TRUE);
        case 'f': return literal("false", Boolean.FALSE);
        case 'n': return literal("null", null);
        default:
          if (c == '-' || (c >= '0' && c <= '9')) return number();
          throw error("unexpected character");
      }
    }

    private Object literal(String word, Object value) {
      if (!text.startsWith(word, pos)) throw error("invalid literal");
      pos += word.length();
      return value;
    }

    private Map<String, Object> object(int depth) {
      Map<String, Object> result = new LinkedHashMap<>();
      pos++;
      space();
      if (pos < text.length() && text.charAt(pos) == '}') { pos++; return result; }
      while (true) {
        space();
        if (pos >= text.length() || text.charAt(pos) != '"') throw error("expected member name");
        String key = string();
        space();
        if (pos >= text.length() || text.charAt(pos) != ':') throw error("expected ':'");
        pos++;
        space();
        if (result.containsKey(key)) throw error("duplicate member " + key);
        result.put(key, value(depth + 1));
        space();
        if (pos >= text.length()) throw error("unterminated object");
        char c = text.charAt(pos++);
        if (c == '}') return result;
        if (c != ',') throw error("expected ',' or '}'");
      }
    }

    private List<Object> array(int depth) {
      List<Object> result = new ArrayList<>();
      pos++;
      space();
      if (pos < text.length() && text.charAt(pos) == ']') { pos++; return result; }
      while (true) {
        space();
        result.add(value(depth + 1));
        space();
        if (pos >= text.length()) throw error("unterminated array");
        char c = text.charAt(pos++);
        if (c == ']') return result;
        if (c != ',') throw error("expected ',' or ']'");
      }
    }

    private String string() {
      StringBuilder out = new StringBuilder();
      pos++;
      while (true) {
        if (pos >= text.length()) throw error("unterminated string");
        char c = text.charAt(pos++);
        if (c == '"') return out.toString();
        if (c < 0x20) throw error("control character in string");
        if (c != '\\') { out.append(c); continue; }
        if (pos >= text.length()) throw error("unterminated escape");
        char e = text.charAt(pos++);
        switch (e) {
          case '"': out.append('"'); break;
          case '\\': out.append('\\'); break;
          case '/': out.append('/'); break;
          case 'b': out.append('\b'); break;
          case 'f': out.append('\f'); break;
          case 'n': out.append('\n'); break;
          case 'r': out.append('\r'); break;
          case 't': out.append('\t'); break;
          case 'u':
            if (pos + 4 > text.length()) throw error("short unicode escape");
            try {
              out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
            } catch (NumberFormatException cause) {
              throw error("invalid unicode escape");
            }
            pos += 4;
            break;
          default: throw error("invalid escape");
        }
      }
    }

    private BigDecimal number() {
      int start = pos;
      if (text.charAt(pos) == '-') pos++;
      while (pos < text.length() && "0123456789.eE+-".indexOf(text.charAt(pos)) >= 0) pos++;
      String token = text.substring(start, pos);
      if (!token.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")) throw error("invalid number");
      return new BigDecimal(token);
    }

    static String write(Object value) {
      StringBuilder out = new StringBuilder();
      write(out, value);
      return out.toString();
    }

    private static void write(StringBuilder out, Object value) {
      if (value == null) out.append("null");
      else if (value instanceof String text) quote(out, text);
      else if (value instanceof Boolean flag) out.append(flag.booleanValue());
      else if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte)
        out.append(((Number) value).longValue());
      else if (value instanceof BigDecimal decimal) out.append(decimal.toString());
      else if (value instanceof Number number) {
        double d = number.doubleValue();
        if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("Non-finite JSON number");
        out.append(BigDecimal.valueOf(d).stripTrailingZeros().toPlainString());
      } else if (value instanceof Map<?, ?> map) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
          if (!first) out.append(',');
          first = false;
          quote(out, String.valueOf(entry.getKey()));
          out.append(':');
          write(out, entry.getValue());
        }
        out.append('}');
      } else if (value instanceof Iterable<?> items) {
        out.append('[');
        boolean first = true;
        for (Object item : items) {
          if (!first) out.append(',');
          first = false;
          write(out, item);
        }
        out.append(']');
      } else throw new IllegalArgumentException("Unsupported JSON value: " + value.getClass().getName());
    }

    private static void quote(StringBuilder out, String text) {
      out.append('"');
      for (int i = 0; i < text.length(); i++) {
        char c = text.charAt(i);
        switch (c) {
          case '"': out.append("\\\""); break;
          case '\\': out.append("\\\\"); break;
          case '\n': out.append("\\n"); break;
          case '\r': out.append("\\r"); break;
          case '\t': out.append("\\t"); break;
          case '\b': out.append("\\b"); break;
          case '\f': out.append("\\f"); break;
          default:
            boolean loneSurrogate = Character.isSurrogate(c) && !(Character.isHighSurrogate(c)
                && i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1)));
            if (Character.isHighSurrogate(c) && !loneSurrogate) {
              out.append(c).append(text.charAt(++i));
            } else if (c < 0x20 || c == 0x2028 || c == 0x2029 || loneSurrogate) {
              out.append(String.format("\\u%04x", (int) c));
            } else out.append(c);
        }
      }
      out.append('"');
    }
  }

  static <V> Map<String, V> fields(Object... pairs) {
    Map<String, V> map = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      @SuppressWarnings("unchecked") V value = (V) pairs[i + 1];
      map.put((String) pairs[i], value);
    }
    return map;
  }

  // ── Text helpers matching the documented truncation and failure markers ───

  /** UTF-8 byte truncation on a code point boundary, with a parseable notice. */
  static String truncateToBytes(String text, int maxBytes) {
    if (text == null) return "";
    if (maxBytes <= 0) return "";
    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
    if (bytes.length <= maxBytes) return text;
    int end = maxBytes;
    while (end > 0 && (bytes[end] & 0xC0) == 0x80) end--;
    return new String(bytes, 0, end, StandardCharsets.UTF_8)
        + "\n\n... [truncated: exceeds " + maxBytes + " bytes, total " + bytes.length + " bytes]";
  }

  /** JADX comments that mean no usable Java body was produced for a method. */
  static final List<String> STRONG_FAILURE_MARKERS = List.of(
      "Code decompiled incorrectly, please refer to instructions dump",
      "Method not decompiled",
      "Method code generation error",
      "Can't load method instructions",
      "Method dump skipped, instruction units count");
  /** Reported, but JADX often still emits usable code. */
  static final List<String> SOFT_FAILURE_MARKERS = List.of("unreachable blocks", "Failed to decompile");

  static List<String> failureMarkers(String code) {
    List<String> out = new ArrayList<>();
    if (code.isEmpty()) return out;
    String lower = code.toLowerCase(java.util.Locale.ROOT);
    for (String marker : STRONG_FAILURE_MARKERS)
      if (lower.contains(marker.toLowerCase(java.util.Locale.ROOT))) out.add(marker);
    for (String marker : SOFT_FAILURE_MARKERS)
      if (lower.contains(marker.toLowerCase(java.util.Locale.ROOT))) out.add(marker);
    return out;
  }

  private static final Pattern METHOD_DIRECTIVE = Pattern.compile("^\\s*\\.method\\b(.*)$");

  /** Every `.method ... .end method` block in class smali whose method name matches. */
  static List<String> smaliMethodBlocks(String smali, String methodName) {
    List<String> out = new ArrayList<>();
    boolean inMethod = false;
    boolean capture = false;
    StringBuilder buffer = new StringBuilder();
    for (String line : smali.split("\n", -1)) {
      if (!inMethod) {
        Matcher match = METHOD_DIRECTIVE.matcher(line);
        if (match.find()) {
          inMethod = true;
          capture = smaliMethodName(match.group(1)).equals(methodName);
          if (capture) { buffer.setLength(0); buffer.append(line); }
        }
      } else {
        if (capture) buffer.append('\n').append(line);
        if (line.stripLeading().startsWith(".end method")) {
          if (capture) out.add(buffer.toString().stripTrailing());
          inMethod = false;
          capture = false;
        }
      }
    }
    if (inMethod && capture && buffer.length() > 0) out.add(buffer.toString().stripTrailing());
    return out;
  }

  static String smaliMethodName(String afterDirective) {
    int paren = afterDirective.indexOf('(');
    String head = (paren >= 0 ? afterDirective.substring(0, paren) : afterDirective).trim();
    String[] tokens = head.split("[ \t]+");
    return tokens[tokens.length - 1].trim();
  }

  private static final Pattern MANIFEST_PACKAGE = Pattern.compile("<manifest\\b[^>]*\\bpackage=\"([^\"]+)\"");
  private static final Pattern VERSION_NAME = Pattern.compile("android:versionName=\"([^\"]+)\"");
  private static final Pattern VERSION_CODE = Pattern.compile("android:versionCode=\"([^\"]+)\"");
  private static final Pattern MIN_SDK = Pattern.compile("android:minSdkVersion=\"([^\"]+)\"");
  private static final Pattern TARGET_SDK = Pattern.compile("android:targetSdkVersion=\"([^\"]+)\"");
  private static final Pattern PERMISSION = Pattern.compile("<uses-permission\\b[^>]*android:name=\"([^\"]+)\"");

  private static String first(Pattern pattern, String text) {
    Matcher match = pattern.matcher(text);
    return match.find() ? match.group(1) : "";
  }

  /** Summary fields from JADX's decoded manifest text; the XML itself is returned separately. */
  static Map<String, Object> manifestSummary(String xml) {
    List<String> permissions = new ArrayList<>();
    Matcher match = PERMISSION.matcher(xml);
    while (match.find()) permissions.add(match.group(1));
    return fields("package", first(MANIFEST_PACKAGE, xml), "version_name", first(VERSION_NAME, xml),
        "version_code", first(VERSION_CODE, xml), "min_sdk", first(MIN_SDK, xml),
        "target_sdk", first(TARGET_SDK, xml), "permissions", permissions);
  }

  // ── One loaded artifact ───────────────────────────────────────────────────

  record SmartCode(String text, String kind, boolean fellBack, List<String> markers) {}

  /** One JadxDecompiler over one admitted file; all code generation runs on one worker. */
  static final class Engine implements AutoCloseable {
    final JadxDecompiler decompiler;
    final String apkPath;
    final int maxSourceBytes;
    final List<String> classFqns;
    final int resourceCount;
    private ExecutorService worker = newWorker();
    private final LinkedHashMap<String, JavaClass> decompiled = new LinkedHashMap<>(16, 0.75f, true);
    private String manifest;
    private boolean manifestLoaded;

    private Engine(JadxDecompiler decompiler, String apkPath, int maxSourceBytes) {
      this.decompiler = decompiler;
      this.apkPath = apkPath;
      this.maxSourceBytes = maxSourceBytes;
      this.classFqns = decompiler.getClasses().stream().map(JavaClass::getFullName).toList();
      this.resourceCount = decompiler.getResources().size();
    }

    static Engine open(String path, int maxSourceBytes) {
      File file = new File(path);
      if (!file.exists()) throw new IllegalArgumentException("APK not found: " + path);
      if (!file.isFile()) throw new IllegalArgumentException("Not a regular file: " + path);
      JadxArgs args = new JadxArgs();
      args.setInputFile(file);
      // Never written: the bridge only loads and reads code in memory.
      args.setOutDir(new File("jadx-output"));
      args.setSkipFilesSave(true);
      args.setShowInconsistentCode(true);
      args.setThreadsCount(1);
      // Keep class names identical to runtime names; no case-insensitive rename pass.
      args.setFsCaseSensitive(true);
      args.setPluginLoader(new AdmittedPluginLoader());
      JadxDecompiler decompiler = new JadxDecompiler(args);
      try {
        decompiler.load();
        return new Engine(decompiler, path, maxSourceBytes);
      } catch (RuntimeException | Error failure) {
        decompiler.close();
        throw failure;
      }
    }

    private static ExecutorService newWorker() {
      return Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "rea-jadx-decompile");
        thread.setDaemon(true);
        return thread;
      });
    }

    /** Run JADX code generation with a wall-clock bound; a stuck worker is abandoned. */
    <T> T timed(String what, Supplier<T> body) throws Exception {
      ExecutorService pool = worker;
      Future<T> future = pool.submit(body::get);
      try {
        return future.get(DECOMPILE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
      } catch (TimeoutException timeout) {
        future.cancel(true);
        pool.shutdownNow();
        worker = newWorker();
        throw new TimeoutException("decompile " + what + " timed out after " + DECOMPILE_TIMEOUT_MS + "ms");
      } catch (ExecutionException failure) {
        Throwable cause = failure.getCause() == null ? failure : failure.getCause();
        if (cause instanceof Exception exception) throw exception;
        throw new RuntimeException(cause);
      }
    }

    /** Bound retained generated code by unloading the least recently used top-level class. */
    void remember(JavaClass cls) {
      JavaClass top = cls.getTopParentClass() == null ? cls : cls.getTopParentClass();
      decompiled.put(top.getRawName(), top);
      if (decompiled.size() <= DECOMPILED_CLASS_CACHE) return;
      Map.Entry<String, JavaClass> eldest = decompiled.entrySet().iterator().next();
      decompiled.remove(eldest.getKey());
      if (eldest.getValue() != top) {
        try { eldest.getValue().unload(); } catch (RuntimeException ignored) { /* best effort */ }
      }
    }

    String methodSource(JavaMethod method) {
      try {
        String text = timed(method.getFullName(), () -> {
          String code = method.getCodeStr();
          return code == null || code.isEmpty()
              ? "// method exists but has no decompiled body (native/abstract)" : code;
        });
        if (method.getDeclaringClass() != null) remember(method.getDeclaringClass());
        return text;
      } catch (Exception failure) {
        return "// ERROR: decompile timed out or failed for " + method.getFullName() + ": " + failure.getMessage();
      }
    }

    /** Smali blocks for a method name, or null when class disassembly is unavailable. */
    List<String> methodSmali(JavaClass cls, String methodName) {
      String smali;
      try {
        smali = timed(cls.getFullName(), () -> {
          String code = cls.getSmali();
          return code == null ? "" : code;
        });
      } catch (Exception failure) {
        return List.of();
      }
      remember(cls);
      if (smali.isEmpty()) return List.of();
      return smaliMethodBlocks(smali, methodName);
    }

    /** Java for one method, or its smali when JADX reports that the Java is not usable. */
    SmartCode methodBody(JavaMethod method) {
      String java = methodSource(method);
      List<String> markers = failureMarkers(java);
      if (markers.stream().anyMatch(STRONG_FAILURE_MARKERS::contains) && method.getDeclaringClass() != null) {
        List<String> blocks = methodSmali(method.getDeclaringClass(), method.getName());
        if (!blocks.isEmpty()) {
          String header = "// [jadx java-decompile failed → smali]\n"
              + "// target: " + method.getFullName() + "\n"
              + "// markers: " + String.join("; ", markers) + "\n"
              + "// (Java body was an anti-decompile stub; showing smali.)\n\n";
          return new SmartCode(truncateToBytes(header + String.join("\n\n", blocks), maxSourceBytes),
              "smali", true, markers);
        }
      }
      return new SmartCode(truncateToBytes(java, maxSourceBytes), "java", false, markers);
    }

    /** Decoded AndroidManifest.xml text as JADX produced it, or null. */
    String manifest() {
      if (manifestLoaded) return manifest;
      manifestLoaded = true;
      for (ResourceFile resource : decompiler.getResources()) {
        String name = resource.getDeobfName().toLowerCase(java.util.Locale.ROOT);
        if (!name.endsWith("androidmanifest.xml")) continue;
        try {
          ResContainer container = resource.loadContent();
          if (container.getDataType() == ResContainer.DataType.TEXT)
            manifest = container.getText().getCodeStr();
        } catch (RuntimeException ignored) {
          manifest = null;
        }
        break;
      }
      return manifest;
    }

    @Override
    public void close() {
      worker.shutdownNow();
      decompiler.close();
    }
  }

  /** Upstream's service loader, narrowed to the input and metadata plugins REA admits. */
  static final class AdmittedPluginLoader implements JadxPluginLoader {
    private final JadxBasePluginLoader delegate = new JadxBasePluginLoader();

    @Override
    public List<JadxPlugin> load() {
      return delegate.load().stream()
          .filter(plugin -> ADMITTED_PLUGINS.contains(plugin.getClass().getName())).toList();
    }

    @Override
    public void close() throws java.io.IOException { delegate.close(); }
  }

  // ── Tool layer ─────────────────────────────────────────────────────────────

  record Reply(String text, boolean failed) {}

  static final class InputFailure extends IllegalArgumentException {
    final String field;
    InputFailure(String field, String message) { super(message); this.field = field; }
  }

  private record MethodSnapshot(String name, String shortId, Map<String, Object> summary) {}
  private record ClassSnapshot(JavaClass node, List<MethodSnapshot> methods, Map<String, Object> summary) {}

  private Engine engine;
  private Engine indexedEngine;
  private Map<String, List<ClassSnapshot>> classes = Map.of();

  ReaJadxBridge() {}

  /** Replace any loaded artifact with one opened at the given source byte bound. */
  Map<String, Object> load(String path, int maxSourceBytes) {
    unload();
    long started = System.currentTimeMillis();
    engine = Engine.open(path, maxSourceBytes);
    return fields("state", "LOADED", "apk_path", engine.apkPath,
        "class_count", engine.classFqns.size(), "raw_class_count", engine.classFqns.size(),
        "resource_count", engine.resourceCount,
        "load_duration_ms", System.currentTimeMillis() - started,
        "decompile_timeout_ms", DECOMPILE_TIMEOUT_MS, "threads", 1,
        "code_cache_size", DECOMPILED_CLASS_CACHE, "resources", "full");
  }

  void unload() {
    Engine current = engine;
    engine = null;
    indexedEngine = null;
    classes = Map.of();
    if (current != null) current.close();
  }

  /** The loaded decompiler, for in-process regressions. */
  JadxDecompiler decompiler() { return engine().decompiler; }

  private Engine engine() {
    if (engine == null) throw new IllegalArgumentException("No APK loaded");
    return engine;
  }

  private static String string(Map<String, Object> args, String name) {
    Object value = args.get(name);
    if (!(value instanceof String text)) throw new IllegalArgumentException(name + " must be a string");
    return text;
  }

  private static int integer(Map<String, Object> args, String name, int fallback) {
    Object value = args.get(name);
    if (value == null) return fallback;
    if (!(value instanceof BigDecimal number))
      throw new IllegalArgumentException(name + " must be a nonnegative integer");
    try {
      int result = number.intValueExact();
      if (result < 0) throw new ArithmeticException();
      return result;
    } catch (ArithmeticException error) {
      throw new IllegalArgumentException(name + " must be a nonnegative integer", error);
    }
  }

  private ClassSnapshot selected(Map<String, Object> args) {
    Engine current = engine();
    if (indexedEngine != current) {
      Map<String, List<ClassSnapshot>> index = new LinkedHashMap<>();
      // JavaClass.getMethods/getFields/getInnerClasses all load code. Raw nodes do not.
      // Snapshot every identity before code generation can rewrite aliases or members.
      for (JavaClass cls : current.decompiler.getClassesWithInners()) {
        ClassNode node = cls.getClassNode();
        List<MethodNode> ordered = new ArrayList<>(node.getMethods());
        ordered.sort(Comparator.comparing(MethodNode::getAlias));
        List<MethodSnapshot> methods = ordered.stream().map(method -> {
          String name = method.getAlias();
          String shortId = method.getMethodInfo().getShortId();
          String rawName = method.getMethodInfo().getName();
          if (!shortId.startsWith(rawName + "("))
            throw new IllegalStateException("JADX method ID has no raw-name prefix: " + shortId);
          String descriptor = shortId.substring(rawName.length());
          String signature = name + "(" + method.getArgTypes().stream()
              .map(Object::toString).collect(Collectors.joining(", "))
              + "): " + method.getReturnType().toString();
          return new MethodSnapshot(name, shortId, ReaJadxBridge.<Object>fields(
              "name", name, "signature", signature, "dex_descriptor", descriptor,
              "is_constructor", method.isConstructor(), "def_pos", 0));
        }).toList();
        List<Map<String, Object>> fieldList = node.getFields().stream()
            .sorted(Comparator.comparing(FieldNode::getAlias))
            .map(field -> ReaJadxBridge.<Object>fields("name", field.getAlias(),
                "type", field.getType().toString(), "def_pos", 0)).toList();
        List<String> inner = node.getInnerClasses().stream().map(ClassNode::getFullName).toList();
        Map<String, Object> summary = fields(
            "full_name", cls.getFullName(), "name", cls.getName(),
            "method_count", methods.size(), "field_count", fieldList.size(),
            "inner_class_count", inner.size(), "inner_classes", inner,
            "methods", methods.stream().map(MethodSnapshot::summary).toList(), "fields", fieldList);
        index.computeIfAbsent(cls.getFullName(), ignored -> new ArrayList<>())
            .add(new ClassSnapshot(cls, methods, summary));
      }
      classes = Collections.unmodifiableMap(index);
      indexedEngine = current;
    }
    String name = string(args, "class_name");
    List<ClassSnapshot> candidates = classes.get(name);
    if (candidates == null) throw new InputFailure("class_name", "Exact class not found: " + name
        + "; use search_android_classes to discover fully qualified names.");
    if (candidates.size() != 1) throw new InputFailure("class_name", "Ambiguous metadata class identity: " + name
        + "; raw identities: " + candidates.stream().map(candidate -> candidate.node().getRawName()).toList());
    return candidates.get(0);
  }

  private List<MethodSnapshot> methods(ClassSnapshot cls, Map<String, Object> args) {
    String name = string(args, "method_name");
    List<MethodSnapshot> result = cls.methods().stream().filter(method -> method.name().equals(name)).toList();
    if (result.isEmpty()) throw new InputFailure("method_name", "Method not found: " + name
        + "; use inspect_android_class to discover available methods.");
    return result;
  }

  private JavaMethod method(ClassSnapshot cls, MethodSnapshot selected) {
    JavaMethod result = cls.node().searchMethodByShortId(selected.shortId());
    if (result == null) throw new IllegalArgumentException("Method identity no longer available: " + selected.shortId());
    return result;
  }

  private SmartCode methodBody(Engine current, ClassSnapshot cls, MethodSnapshot selected, JavaMethod method) {
    if (!selected.shortId().equals("<clinit>()V")) return current.methodBody(method);
    // Java code generation can fold all or part of <clinit> into field declarations.
    // Its method text cannot establish coverage, even when a static block remains.
    List<String> blocks = current.methodSmali(cls.node(), method.getName());
    if (blocks.size() != 1)
      throw new IllegalArgumentException("Static initializer disassembly requires one exact method: " + selected.shortId());
    return new SmartCode(truncateToBytes(blocks.get(0), current.maxSourceBytes),
        "smali", true, List.of("static_initializer_disassembly"));
  }

  // The TypeScript transport admits 8 MiB frames. Reserve 1 KiB for the fixed
  // JSON-RPC/tool-result envelope and request id, and account for JSON text
  // being escaped again inside the text content.
  private static final int MAX_XREF_TEXT_BYTES = 8 * 1024 * 1024 - 1024;
  private static int escapedJsonBytes(Object value) {
    return Json.write(Json.write(value)).getBytes(StandardCharsets.UTF_8).length;
  }
  private static final class InvokeBudget {
    long remaining;
    InvokeBudget(long remaining) { this.remaining = Math.max(0, remaining); }
    boolean admit(Map<String, Object> site) {
      // Check a conservative two-layer escape bound before serialization.
      long bound = 256;
      for (Object value : site.values())
        if (value instanceof String text) bound += 12L * text.length();
      if (bound > remaining) return false;
      long bytes = escapedJsonBytes(site) - 2L + 1L;
      if (bytes > remaining) return false;
      remaining -= bytes;
      return true;
    }
  }
  private record DirectInvokes(List<Map<String, Object>> sites, boolean exhaustive) {}

  /** Raw DEX invokes within one JADX using method; offsets are code units from its code start. */
  private static DirectInvokes directInvokes(JavaMethod source, MethodInfo target, InvokeBudget budget) {
    MethodNode node = source.getMethodNode();
    ICodeReader code = node.getCodeReader();
    if (code == null) return null;
    List<Map<String, Object>> sites = new ArrayList<>();
    boolean[] exhaustive = {true};
    code.visitInstructions(insn -> {
      insn.decode();
      if (insn.getIndexType() != InsnIndexType.METHOD_REF) return;
      Opcode opcode = insn.getOpcode();
      if (!opcode.name().startsWith("INVOKE_")) return;
      IMethodRef ref = insn.getIndexAsMethod();
      ref.load();
      if (!MethodInfo.fromRef(node.root(), ref).getRawFullId().equals(target.getRawFullId())) return;
      Map<String, Object> site = fields(
          "dex_entry", node.getInputFileName(),
          "source_raw_method_id", node.getMethodInfo().getRawFullId(),
          "dex_code_unit_offset", insn.getOffset(),
          "dex_method_index", insn.getIndex(),
          "opcode", opcode.name());
      if (budget.admit(site)) sites.add(site);
      else exhaustive[0] = false;
    });
    return new DirectInvokes(sites, exhaustive[0]);
  }

  /** One using node, without resolving source lines (which would force code generation). */
  private static Map<String, Object> describeUsage(JavaNode node) {
    String declaring = "";
    try {
      JavaClass owner = node.getDeclaringClass();
      if (owner != null) declaring = owner.getFullName();
    } catch (RuntimeException ignored) { /* reported as unknown */ }
    String kind = node instanceof JavaClass ? "class"
        : node instanceof JavaMethod ? "method"
        : node instanceof JavaField ? "field" : node.getClass().getSimpleName();
    JavaClass top = null;
    try { top = node.getTopParentClass(); } catch (RuntimeException ignored) { /* unknown */ }
    int defPos = 0;
    try { defPos = node.getDefPos(); } catch (RuntimeException ignored) { /* unknown */ }
    return fields("kind", kind,
        "name", node.getName() == null ? "" : node.getName(),
        "full_name", node.getFullName() == null ? "" : node.getFullName(),
        "containing_class", declaring,
        "top_class", top == null ? declaring : top.getFullName(),
        "def_pos", defPos);
  }

  /** Execute one tool. Selector failures are structured; other failures are text. */
  Reply call(String name, Map<String, Object> args) {
    try {
      Object value = handle(name, args);
      return value instanceof String text ? new Reply(text, false) : new Reply(Json.write(value), false);
    } catch (InputFailure error) {
      return new Reply(Json.write(fields("kind", "invalid-input", "field", error.field,
          "message", error.getMessage())), true);
    } catch (IllegalArgumentException error) {
      return new Reply(error.getMessage(), true);
    } catch (RuntimeException | StackOverflowError | OutOfMemoryError error) {
      String message = error.getMessage();
      return new Reply(name + " failed: " + (message == null ? error.getClass().getSimpleName() : message), true);
    }
  }

  private Object handle(String name, Map<String, Object> args) {
    switch (name) {
      case "rea_jvm_status":
        return fields("engine_reported_version", Jadx.getVersion(),
            "max_heap_bytes", Runtime.getRuntime().maxMemory(),
            "available_processors", Runtime.getRuntime().availableProcessors(),
            "java_version", System.getProperty("java.version"),
            "metadata_scope", "parsed_members");
      case "load_apk":
        try {
          return load(string(args, "path"), DEFAULT_MAX_SOURCE_BYTES);
        } catch (RuntimeException failure) {
          throw new IllegalArgumentException("load failed: " + failure.getMessage(), failure);
        }
      case "get_app_info": {
        String xml = engine().manifest();
        if (xml == null) throw new IllegalArgumentException("AndroidManifest.xml not found");
        return manifestSummary(xml);
      }
      case "get_android_manifest": {
        Engine current = engine();
        String xml = current.manifest();
        if (xml == null) throw new IllegalArgumentException("AndroidManifest.xml not found");
        return truncateToBytes(xml, current.maxSourceBytes);
      }
      case "list_classes": {
        List<String> names = engine().classFqns;
        int offset = integer(args, "offset", 0);
        int limit = integer(args, "limit", 200);
        int start = Math.min(offset, names.size());
        int end = (int) Math.min((long) start + limit, names.size());
        return fields("total", names.size(), "offset", offset, "limit", limit,
            "items", names.subList(start, end));
      }
      case "get_class_summary":
        return selected(args).summary();
      case "get_method_body": {
        Engine current = engine();
        ClassSnapshot cls = selected(args);
        List<MethodSnapshot> overloads = methods(cls, args);
        int index = integer(args, "overload_index", 0);
        if (index >= overloads.size()) throw new InputFailure("overload_index", "overload_index out of range: " + index);
        JavaMethod method = method(cls, overloads.get(index));
        SmartCode code = methodBody(current, cls, overloads.get(index), method);
        return fields("class_name", cls.summary().get("full_name"),
            "method_name", overloads.get(index).name(), "full_name", method.getFullName(),
            "overload_index", index, "overload_count", overloads.size(),
            "mode", code.kind(), "fell_back", code.fellBack(),
            "markers", code.markers(), "body", code.text());
      }
      case "get_xrefs_to_class":
      case "get_xrefs_to_method":
        return references(name, args);
      default:
        throw new IllegalArgumentException("Unknown tool: " + name);
    }
  }

  private Map<String, Object> references(String name, Map<String, Object> args) {
    ClassSnapshot cls = selected(args);
    List<JavaNode> uses;
    String target = string(args, "class_name");
    MethodSnapshot selectedMethod = null;
    int overloadIndex = 0;
    if (name.equals("get_xrefs_to_class")) uses = cls.node().getUseIn();
    else {
      List<MethodSnapshot> overloads = methods(cls, args);
      if (overloads.size() != 1 && !args.containsKey("overload_index"))
        throw new InputFailure("overload_index", "Select one of " + overloads.size() + " method overloads");
      overloadIndex = integer(args, "overload_index", 0);
      if (overloadIndex >= overloads.size())
        throw new InputFailure("overload_index", "overload_index out of range: " + overloadIndex);
      selectedMethod = overloads.get(overloadIndex);
      target += "." + selectedMethod.name();
      uses = method(cls, selectedMethod).getUseIn();
    }
    // REA consumes all references without materializing source line information.
    MethodInfo targetInfo = selectedMethod == null ? null
        : method(cls, selectedMethod).getMethodNode().getMethodInfo();
    List<Map<String, Object>> items = new ArrayList<>();
    for (JavaNode node : uses) {
      Map<String, Object> item = describeUsage(node);
      if (targetInfo != null && node instanceof JavaMethod) {
        item.put("direct_invokes", List.of());
        item.put("direct_invokes_exhaustive", false);
      }
      items.add(item);
    }
    Map<String, Object> result = fields("target", target,
        "total", uses.size(), "count", items.size(), "resolve_line", false, "items", items);
    if (selectedMethod != null) {
      result.put("overload_index", overloadIndex);
      result.put("reported_signature", selectedMethod.summary().get("signature"));
    }
    if (targetInfo != null) {
      InvokeBudget budget = new InvokeBudget(MAX_XREF_TEXT_BYTES - escapedJsonBytes(result));
      for (int index = 0; index < uses.size(); index++) {
        if (!(uses.get(index) instanceof JavaMethod source)) continue;
        DirectInvokes invokes = directInvokes(source, targetInfo, budget);
        Map<String, Object> item = items.get(index);
        if (invokes == null) {
          item.remove("direct_invokes");
          item.remove("direct_invokes_exhaustive");
        } else {
          item.put("direct_invokes", invokes.sites());
          item.put("direct_invokes_exhaustive", invokes.exhaustive());
        }
      }
    }
    return result;
  }

  // ── Wire protocol ──────────────────────────────────────────────────────────

  private static Map<String, Object> schema(Map<String, Object> properties, List<String> required) {
    return fields("type", "object", "properties", properties, "required", required);
  }

  private static Map<String, Object> property(String type, String description) {
    return fields("type", type, "description", description);
  }

  static List<Map<String, Object>> toolDefinitions() {
    Map<String, Object> className = property("string", "Exact fully qualified class name.");
    Map<String, Object> methodName = property("string", "Exact method name as listed by get_class_summary.");
    Map<String, Object> overload = property("integer", "Zero-based index among same-name methods in get_class_summary order.");
    return List.of(
        fields("name", "rea_jvm_status", "description", "Observed worker JVM, upstream JADX version and metadata scope.",
            "inputSchema", schema(fields(), List.of())),
        fields("name", "load_apk", "description", "Load one APK with one JADX worker thread; replaces any loaded file.",
            "inputSchema", schema(fields("path", property("string", "Absolute path to the admitted APK."),
                "threads", property("integer", "Must be 1."), "resources", property("string", "Must be full.")),
                List.of("path"))),
        fields("name", "get_app_info", "description", "Package, version, SDK levels and permissions extracted from JADX's decoded AndroidManifest.xml.",
            "inputSchema", schema(fields(), List.of())),
        fields("name", "get_android_manifest", "description", "JADX's decoded AndroidManifest.xml, byte-bounded with a truncation notice.",
            "inputSchema", schema(fields(), List.of())),
        fields("name", "list_classes", "description", "Indexed pages of all top-level class names, with offset and limit.",
            "inputSchema", schema(fields("offset", property("integer", "First index."),
                "limit", property("integer", "Maximum page size.")), List.of())),
        fields("name", "get_class_summary", "description", "Parsed member metadata for one exact class name; no source generation.",
            "inputSchema", schema(fields("class_name", className), List.of("class_name"))),
        fields("name", "get_method_body", "description", "Source for an exact class and stable same-name overload index; static initializers use smali to preserve folded field initialization.",
            "inputSchema", schema(fields("class_name", className, "method_name", methodName,
                "overload_index", overload), List.of("class_name", "method_name"))),
        fields("name", "get_xrefs_to_class", "description", "Complete static using-node inventory for an exact class; source lines are unresolved.",
            "inputSchema", schema(fields("class_name", className), List.of("class_name"))),
        fields("name", "get_xrefs_to_method", "description", "Complete static using-node inventory for a selected method overload; one node may contain multiple invoke instructions, and source lines are unresolved.",
            "inputSchema", schema(fields("class_name", className, "method_name", methodName,
                "overload_index", overload), List.of("class_name", "method_name"))));
  }

  /** Handle one JSON-RPC line; returns the reply line, or null for notifications. */
  String dispatch(String line) {
    Object parsed;
    try {
      parsed = Json.parse(line);
    } catch (IllegalArgumentException failure) {
      return Json.write(fields("jsonrpc", "2.0", "id", null,
          "error", fields("code", -32700, "message", failure.getMessage())));
    }
    if (!(parsed instanceof Map<?, ?> raw) || !(raw.get("method") instanceof String method)) {
      if (parsed instanceof Map<?, ?> response && response.containsKey("id") && !response.containsKey("method"))
        return null; // A response to nothing this bridge sent.
      return Json.write(fields("jsonrpc", "2.0", "id", null,
          "error", fields("code", -32600, "message", "Invalid request")));
    }
    if (!raw.containsKey("id")) return null; // notifications/initialized, notifications/cancelled
    Object id = raw.get("id");
    @SuppressWarnings("unchecked")
    Map<String, Object> params = raw.get("params") instanceof Map<?, ?> map
        ? (Map<String, Object>) map : Map.of();
    Object result;
    switch (method) {
      case "initialize": {
        Object requested = params.get("protocolVersion");
        result = fields("protocolVersion", requested instanceof String version ? version : FALLBACK_PROTOCOL_VERSION,
            "capabilities", fields("tools", fields("listChanged", false)),
            "serverInfo", fields("name", NAME, "version", VERSION));
        break;
      }
      case "ping":
        result = fields();
        break;
      case "tools/list":
        result = fields("tools", toolDefinitions());
        break;
      case "tools/call": {
        if (!(params.get("name") instanceof String tool))
          return Json.write(fields("jsonrpc", "2.0", "id", id,
              "error", fields("code", -32602, "message", "tools/call requires a tool name")));
        @SuppressWarnings("unchecked")
        Map<String, Object> arguments = params.get("arguments") instanceof Map<?, ?> map
            ? (Map<String, Object>) map : Map.of();
        Reply reply = call(tool, arguments);
        result = fields("content", List.of(fields("type", "text", "text", reply.text())),
            "isError", reply.failed());
        break;
      }
      default:
        return Json.write(fields("jsonrpc", "2.0", "id", id,
            "error", fields("code", -32601, "message", "Method not found: " + method)));
    }
    return Json.write(fields("jsonrpc", "2.0", "id", id, "result", result));
  }

  public static void main(String[] args) throws Exception {
    // Engine logging must never corrupt the protocol stream.
    OutputStream protocol = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), false,
        StandardCharsets.UTF_8);
    System.setOut(System.err);
    ReaJadxBridge bridge = new ReaJadxBridge();
    try (BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
      String line;
      while ((line = input.readLine()) != null) {
        if (line.isBlank()) continue;
        String reply = bridge.dispatch(line);
        if (reply == null) continue;
        protocol.write((reply + "\n").getBytes(StandardCharsets.UTF_8));
        protocol.flush();
      }
    } finally {
      bridge.unload();
    }
  }
}

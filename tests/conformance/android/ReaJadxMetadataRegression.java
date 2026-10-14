import com.android.tools.smali.smali.Smali;
import com.android.tools.smali.smali.SmaliOptions;
import jadx.api.*;
import jadx.core.dex.nodes.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Real upstream-JADX regression; synthetic protocol fixtures cannot prove absence of code generation. */
public class ReaJadxMetadataRegression {
  private static final int SOURCE_BYTES = 1048576;

  private static void require(boolean condition, String reason) {
    if (!condition) throw new AssertionError(reason);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> call(ReaJadxBridge bridge, String operation, Map<String, Object> arguments) {
    ReaJadxBridge.Reply response = bridge.call(operation, arguments);
    require(!response.failed(), operation + " returned an error: " + response.text());
    return (Map<String, Object>) ReaJadxBridge.Json.parse(response.text());
  }

  private static Map<String, Object> arguments(String className) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("class_name", className);
    return value;
  }

  private static Map<String, Object> methodArguments(String className, String methodName) {
    Map<String, Object> value = arguments(className);
    value.put("method_name", methodName);
    value.put("overload_index", BigDecimal.ZERO);
    return value;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> array(Map<String, Object> value, String name) {
    return (List<Object>) value.get(name);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value) {
    return (Map<String, Object>) value;
  }

  private static int integer(Object value) {
    return ((BigDecimal) value).intValueExact();
  }

  private static Path assemble(Path output, String dex, List<Path> sources) throws Exception {
    SmaliOptions options = new SmaliOptions();
    options.apiLevel = 28;
    options.jobs = 1;
    options.outputDexFile = output.resolve(dex).toString();
    require(Smali.assemble(options, sources.stream().map(Path::toString).toList()), dex + " assembly failed");
    return Path.of(options.outputDexFile);
  }

  private static Path apk(Path output, String name, List<Path> dexFiles) throws Exception {
    Path apk = output.resolve(name);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(apk))) {
      for (int index = 0; index < dexFiles.size(); index++) {
        zip.putNextEntry(new ZipEntry(index == 0 ? "classes.dex" : "classes" + (index + 1) + ".dex"));
        Files.copy(dexFiles.get(index), zip);
        zip.closeEntry();
      }
    }
    return apk;
  }

  private static void verifyDirectInvokes(ReaJadxBridge bridge, Path sources, Path output) throws Exception {
    Path single = apk(output, "direct-invokes.apk", List.of(assemble(output, "direct-invokes.dex",
        List.of(sources.resolve("Caller.smali"), sources.resolve("Target.smali")))));
    bridge.load(single.toString(), SOURCE_BYTES);
    checkDirectInvokes(call(bridge, "get_xrefs_to_method", methodArguments("fixture.Target", "mark")), "classes.dex");

    Path target = assemble(output, "direct-target.dex", List.of(sources.resolve("Target.smali")));
    Path caller = assemble(output, "direct-caller.dex", List.of(sources.resolve("Caller.smali")));
    Path split = apk(output, "direct-invokes-multidex.apk", List.of(target, caller));
    bridge.load(split.toString(), SOURCE_BYTES);
    checkDirectInvokes(call(bridge, "get_xrefs_to_method", methodArguments("fixture.Target", "mark")), "classes2.dex");
    System.out.println("DIRECT_INVOKE_REGRESSION_PASS nodes=1 offsets=0,3 cross_dex=true");
  }

  private static void checkDirectInvokes(Map<String, Object> refs, String dexEntry) {
    require(integer(refs.get("total")) == 1, "JADX using-node count changed");
    List<Object> sites = array(object(array(refs, "items").get(0)), "direct_invokes");
    require(sites.size() == 2, "Raw DEX invoke count differs from the fixture: " + sites);
    for (int i = 0; i < sites.size(); i++) {
      Map<String, Object> site = object(sites.get(i));
      require(site.get("dex_entry").equals(dexEntry), "Wrong DEX entry");
      require(site.get("source_raw_method_id").equals("fixture.Caller.twice()V"), "Wrong raw source method");
      require(integer(site.get("dex_code_unit_offset")) == i * 3, "Wrong DEX offset");
      require(site.get("opcode").equals("INVOKE_STATIC"), "Wrong opcode");
    }
    require(integer(object(sites.get(0)).get("dex_method_index"))
        == integer(object(sites.get(1)).get("dex_method_index")),
        "Two invokes did not reference the same DEX method ID");
  }

  private static void verifyInitializers(ReaJadxBridge bridge, Path sources, Path output) throws Exception {
    Path apk = apk(output, "initializers.apk", List.of(assemble(output, "initializers.dex",
        List.of(sources.resolve("InitializationPolicy.smali"), sources.resolve("MixedInitialization.smali")))));
    bridge.load(apk.toString(), SOURCE_BYTES);
    String[] classNames = { "fixture.InitializationPolicy", "fixture.MixedInitialization" };
    String[][] witnesses = {
        { "declared-policy", "->singletonList", "->POLICY:Ljava/util/List;" },
        { "field-value", "->LABEL:Ljava/lang/String;", "->touch()V" }
    };
    for (int index = 0; index < classNames.length; index++) {
      Map<String, Object> summary = call(bridge, "get_class_summary", arguments(classNames[index]));
      Map<String, Object> input = methodArguments(classNames[index], "<clinit>");
      Map<String, Object> body = call(bridge, "get_method_body", input);
      String text = (String) body.get("body");
      for (String witness : witnesses[index]) require(text.contains(witness), "Missing initializer instruction: " + witness);
      require(body.get("mode").equals("smali"), "Static initializer must preserve DEX instructions");
      require(Boolean.TRUE.equals(body.get("fell_back")), "Disassembly fallback was not reported");
      require(array(body, "markers").contains("static_initializer_disassembly"),
          "Static initializer representation reason was not reported");
      require(text.contains(".method static constructor <clinit>()V") && text.contains(".end method"),
          "Initializer method boundaries missing");
      require(integer(body.get("overload_index")) == 0 && integer(body.get("overload_count")) == 1,
          "Initializer identity changed");
      require(body.equals(call(bridge, "get_method_body", input)), "Repeated initializer body changed");
      require(summary.equals(call(bridge, "get_class_summary", arguments(classNames[index]))),
          "Frozen initializer metadata changed after source generation");
    }
    for (String name : List.of("missing", "originalNative")) {
      Map<String, Object> body = call(bridge, "get_method_body", methodArguments(classNames[0], name));
      String text = (String) body.get("body");
      require(body.get("mode").equals("java") && !text.contains("{") && !text.contains(".method"),
          "Executable body was fabricated for " + name + ": " + text);
    }
    Map<String, Object> ordinary = call(bridge, "get_method_body", methodArguments(classNames[1], "touch"));
    require(ordinary.get("mode").equals("java") && ((String) ordinary.get("body")).contains("COUNT"),
        "Ordinary executable method no longer produces Java");

    bridge.load(apk.toString(), 96);
    Map<String, Object> partial = call(bridge, "get_method_body", methodArguments(classNames[0], "<clinit>"));
    String partialText = (String) partial.get("body");
    require(partial.get("mode").equals("smali") && partialText.contains("[truncated: exceeds 96 bytes, total "),
        "Static initializer ignored the source byte limit or omitted its truncation marker");
    String prefix = partialText.split("\n\n\\.\\.\\. \\[truncated:", 2)[0];
    require(prefix.getBytes(StandardCharsets.UTF_8).length <= 96, "Initializer text exceeded its byte limit");
    System.out.println("INITIALIZER_REGRESSION_PASS folded=2 bounded=true");
  }

  public static void main(String[] args) throws Exception {
    ReaJadxBridge bridge = new ReaJadxBridge();
    try {
      bridge.load(args[0], SOURCE_BYTES);
      JadxDecompiler decompiler = bridge.decompiler();
      require(!decompiler.getClasses().isEmpty(), "Fixture did not load classes");
      IdentityHashMap<ClassNode, ProcessState> states = new IdentityHashMap<>();
      for (ClassNode node : decompiler.getRoot().getClasses()) {
        require(node.getState() == ProcessState.NOT_LOADED, "Fixture unexpectedly generated source");
        states.put(node, node.getState());
      }
      Map<String, Object> apiArgs = arguments("io.appium.android.apis.ApiDemos");
      Map<String, Object> apiSummary = call(bridge, "get_class_summary", apiArgs);
      for (var entry : states.entrySet()) require(entry.getKey().getState() == entry.getValue(),
          "Metadata generated source: " + entry.getKey().getRawName());
      require(states.size() == decompiler.getRoot().getClasses().size(), "Metadata changed class inventory");
      require(((String) object(array(apiSummary, "fields").get(0)).get("type")).contains("Comparator"),
          "Generic field type was truncated");
      Map<String, Object> componentArgs = arguments("androidx.activity.ComponentActivity");
      Map<String, Object> componentSummary = call(bridge, "get_class_summary", componentArgs);
      List<String> signatures = new ArrayList<>();
      List<String> descriptors = new ArrayList<>();
      for (Object entry : array(componentSummary, "methods")) {
        Map<String, Object> method = object(entry);
        if (method.get("name").equals("setContentView")) {
          signatures.add((String) method.get("signature"));
          descriptors.add((String) method.get("dex_descriptor"));
        }
      }
      require(signatures.size() == 3, "Fixture must contain three setContentView overloads");
      require(descriptors.equals(List.of("(I)V", "(Landroid/view/View;)V",
          "(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V")),
          "Frozen DEX prototypes did not identify the three overloads: " + descriptors);
      String[] declarations = { "setContentView(int ", "setContentView(View ", "setContentView(View view, ViewGroup.LayoutParams " };
      List<Integer> referenceCounts = new ArrayList<>();
      for (int index = 0; index < signatures.size(); index++) {
        Map<String, Object> methodArgs = arguments("androidx.activity.ComponentActivity");
        methodArgs.put("method_name", "setContentView");
        methodArgs.put("overload_index", BigDecimal.valueOf(index));
        Map<String, Object> first = call(bridge, "get_method_body", methodArgs);
        require(first.equals(call(bridge, "get_method_body", methodArgs)), "Repeated body changed");
        require(integer(first.get("overload_index")) == index && integer(first.get("overload_count")) == 3,
            "Overload envelope mismatch");
        require(first.get("mode").equals("java"), "Fixture did not produce Java");
        require(((String) first.get("body")).contains(declarations[index]), "Wrong overload: " + signatures.get(index));
        Map<String, Object> references = call(bridge, "get_xrefs_to_method", methodArgs);
        require(integer(references.get("overload_index")) == index,
            "Reference result did not preserve selected overload index");
        require(references.get("reported_signature").equals(signatures.get(index)),
            "Reference result did not preserve selected overload signature");
        if (index == 0) {
          List<Object> invokes = array(object(array(references, "items").get(0)), "direct_invokes");
          require(invokes.size() == 1, "Selected overload must have one raw direct invoke");
          Map<String, Object> invoke = object(invokes.get(0));
          require(invoke.get("source_raw_method_id")
              .equals("androidx.activity.ComponentActivity.onCreate(Landroid/os/Bundle;)V"),
              "Wrong source method for overloaded target");
          require(integer(invoke.get("dex_code_unit_offset")) == 37 && invoke.get("opcode").equals("INVOKE_VIRTUAL"),
              "Wrong direct invoke for selected overloaded target");
        }
        referenceCounts.add(integer(references.get("count")));
      }
      require(referenceCounts.equals(List.of(1, 0, 0)),
          "Incoming references were not isolated to the selected overload: " + referenceCounts);
      require(componentSummary.equals(call(bridge, "get_class_summary", componentArgs)),
          "Frozen summary changed after code generation");
      require(apiSummary.equals(call(bridge, "get_class_summary", apiArgs)), "Unrelated frozen summary changed");
      System.out.println("METADATA_REGRESSION_PASS classes=" + states.size() + " overloads=" + signatures.size()
          + " reference_counts=" + referenceCounts);
      verifyInitializers(bridge, Path.of(args[1]), Path.of(args[2]));
      verifyDirectInvokes(bridge, Path.of(args[3]), Path.of(args[2]));
    } finally {
      bridge.unload();
    }
  }
}

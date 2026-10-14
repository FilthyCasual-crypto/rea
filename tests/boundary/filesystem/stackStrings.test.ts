import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createStackStringsService } from "../../../src/composition/binaryDiagnostics.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const SOURCE = String.raw`
#include <stdio.h>
__attribute__((noinline)) void use(const char *s) { puts(s); }
__attribute__((noinline)) void packed(void) {
  volatile char s[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
  use((const char*)s);
}
__attribute__((noinline)) void perbyte(void) {
  volatile char s[16];
  s[0]='G';s[1]='e';s[2]='t';s[3]='P';s[4]='r';s[5]='o';s[6]='c';s[7]='A';s[8]='d';s[9]='d';s[10]='r';s[11]=0;
  use((const char*)s);
}
__attribute__((noinline)) void perdword(void) {
  volatile int s[4];
  s[0]=0x64616f4c; s[1]=0x7262694c; s[2]=0x41797261; s[3]=0;
  use((const char*)s);
}
int main(void) { packed(); perbyte(); perdword(); return 0; }
`;

const compiler = (() => {
  if (process.platform !== "linux" || process.arch !== "x64") return null;
  try {
    execFileSync("gcc", ["--version"], { stdio: "ignore" });
    return "gcc";
  } catch {
    return null;
  }
})();

const stringsOf = (evidence: { normalized_result: unknown }) =>
  (evidence.normalized_result as { strings: { string: string }[] }).strings.map(
    ({ string }) => string,
  );

describe("stack-string recovery over real executables", () => {
  it.skipIf(compiler === null).each(["-O0", "-O2"])(
    "recovers gcc %s stack strings",
    async (level) => {
      const root = await createTestTempDirectory("rea-stack-strings-");
      const source = join(root, "sample.c");
      const binary = join(root, `sample${level}`);
      await writeFile(source, SOURCE);
      execFileSync(compiler!, [
        level,
        "-fno-stack-protector",
        "-o",
        binary,
        source,
      ]);
      const service = createStackStringsService();
      const result = await service.extract({ path: binary });
      if (!result.ok) throw result.error;
      expect(stringsOf(result.value)).toEqual(
        expect.arrayContaining(["kernel32.dll", "GetProcAddr", "LoadLibraryA"]),
      );
      expect(result.value.normalized_result).toMatchObject({
        architecture: "x86-64",
      });
      await service.close();
    },
  );

  it("reports unsupported formats instead of guessing", async () => {
    const root = await createTestTempDirectory("rea-stack-strings-raw-");
    const path = join(root, "blob.bin");
    await writeFile(path, Buffer.from("not an executable at all"));
    const result = await createStackStringsService().extract({ path });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      architecture: "unknown",
      strings: [],
      scanned_regions: [],
    });
  });
});

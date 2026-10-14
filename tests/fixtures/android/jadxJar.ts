import { JADX_BRIDGE_REQUIRED_CLASSES } from "../../../src/android/JadxConfiguration.js";
import { writeOrderedZip } from "../artifactEntryOrder.js";

/** ZIP classpath inventory for synthetic protocol tests; not executable bytecode. */
export const writeJadxJarInventory = (
  path: string,
  extraEntries: readonly string[] = [],
): Promise<void> =>
  writeOrderedZip(path, [...JADX_BRIDGE_REQUIRED_CLASSES, ...extraEntries]);

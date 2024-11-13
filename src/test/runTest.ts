import * as cp from "child_process";
import * as path from "path";

import {
   downloadAndUnzipVSCode,
   resolveCliArgsFromVSCodeExecutablePath,
   runTests
} from "@vscode/test-electron";

async function main() {
  try {
    // The folder containing the Extension Manifest package.json
    // Passed to `--extensionDevelopmentPath`
    const extensionDevelopmentPath = path.resolve(__dirname, "../../");

    // The path to the extension test script
    // Passed to --extensionTestsPath
    const extensionTestsPath = path.resolve(__dirname, "./suite/index");
    const vscodeExecutablePath = await downloadAndUnzipVSCode("stable");
    const [cli, ...args] = resolveCliArgsFromVSCodeExecutablePath(vscodeExecutablePath);

    const installExtension = (extId) =>
      cp.spawnSync(cli, [...args, "--install-extension", extId], {
        encoding: "utf-8",
        stdio: "inherit",
      });

    // Install dependent extensions
    installExtension("intersystems-community.servermanager");
    installExtension("intersystems-community.vscode-objectscript");

    // Download VS Code, unzip it and run the integration test
    await runTests({ extensionDevelopmentPath, extensionTestsPath });
  } catch (err) {
    console.error("Failed to run tests", err);
    process.exit(1);
  }
}

main();

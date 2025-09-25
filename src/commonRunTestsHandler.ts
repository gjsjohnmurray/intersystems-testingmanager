import * as vscode from 'vscode';
import { IServerSpec } from "@intersystems-community/intersystems-servermanager";
import { allTestRuns, extensionId, osAPI, OurTestItem } from './extension';
import { relativeTestRoot } from './localTests';
import logger from './logger';
import { makeRESTRequest } from './makeRESTRequest';
import { OurFileCoverage } from './ourFileCoverage';

export async function commonRunTestsHandler(controller: vscode.TestController, resolveItemChildren: (item: vscode.TestItem) => Promise<void>, request: vscode.TestRunRequest, cancellation: vscode.CancellationToken) {
  logger.debug(`commonRunTestsHandler invoked by controller id=${controller.id}`);

  // For each authority (i.e. server:namespace) accumulate a map of the class-level Test nodes in the tree.
  // We don't yet support running only some TestXXX methods in a testclass
  const mapAuthorities = new Map<string, Map<string, OurTestItem>>();
  const runIndices: number[] =[];
  const queue: OurTestItem[] = [];
  const coverageRequest = request.profile?.kind === vscode.TestRunProfileKind.Coverage;

  // Loop through all included tests, or all known tests, and add them to our queue
  if (request.include) {
    request.include.forEach((test: OurTestItem) => {
      if (!coverageRequest || test.supportsCoverage) {
        queue.push(test);
      }
    });
  } else {
    // Run was launched from controller's root level
    controller.items.forEach((test: OurTestItem) => {
      if (!coverageRequest || test.supportsCoverage) {
        queue.push(test);
      }
    });
  }

  if (coverageRequest && !queue.length) {
    // No tests to run, but coverage requested
    vscode.window.showErrorMessage("[Test Coverage Tool](https://openexchange.intersystems.com/package/Test-Coverage-Tool) not found.", );
    return;
  }

  // Process every test that was queued. Recurse down to leaves (testmethods) and build a map of their parents (classes)
  while (queue.length > 0 && !cancellation.isCancellationRequested) {
    const test = queue.pop()!;

    // Skip tests the user asked to exclude
    if (request.exclude && request.exclude.filter((excludedTest) => excludedTest.id === test.id).length > 0) {
      continue;
    }

    // Resolve children if not definitely already done
    if (test.canResolveChildren && test.children.size === 0) {
      await resolveItemChildren(test);
    }

    // If a leaf item (a TestXXX method in a class) note its .cls file for copying.
    // Every leaf should have a uri.
    if (test.children.size === 0 && test.uri) {
      let authority = test.uri.authority;
      let key = test.uri.path;
      if (test.uri.scheme === "file") {
        // Client-side editing, for which we will assume objectscript.conn names a server defined in `intersystems.servers`
        const conn: any = vscode.workspace.getConfiguration("objectscript", test.uri).get("conn");
        authority = (conn.server || "") + ":" + (conn.ns as string).toLowerCase();
        const folder = vscode.workspace.getWorkspaceFolder(test.uri);
        if (folder) {
          key = key.slice(folder.uri.path.length + relativeTestRoot(folder).length + 1);
        }
      }

      const mapTestClasses = mapAuthorities.get(authority) || new Map<string, OurTestItem>();
      if (!mapTestClasses.has(key) && test.parent) {
        // When leaf is a test its parent has a uri and is the class
        // Otherwise the leaf is a class with no tests
        mapTestClasses.set(key, test.parent.uri ? test.parent : test);
        mapAuthorities.set(authority, mapTestClasses);
      }
    }

    // Queue any children
    test.children.forEach(test => queue.push(test));
  }

  // Cancelled while building our structures?
  if (cancellation.isCancellationRequested) {
    return;
  }

  if (mapAuthorities.size === 0) {
    // Nothing included
    vscode.window.showErrorMessage("Empty test run.", { modal: true });
    return;
  }

  // Arrange for cancellation to stop the debugging sessions we start
  cancellation.onCancellationRequested(() => {
    runIndices.forEach((runIndex) => {
      const session = allTestRuns[runIndex]?.debugSession;
      if (session) {
        vscode.debug.stopDebugging(session);
      }
    });
  });

  for await (const mapInstance of mapAuthorities) {

    const run = controller.createTestRun(
      request,
      'Test Results',
      true
    );
    let authority = mapInstance[0];
    const mapTestClasses = mapInstance[1];

    // enqueue everything up front so user sees immediately which tests will run
    mapTestClasses.forEach((test) => {
      let methodTarget = "";
      if (request.include?.length === 1) {
        const idParts = request.include[0].id.split(":");
        if (idParts.length === 5) {
          methodTarget = request.include[0].id;
        }
      }
      test.children.forEach((methodTest) => {
        if (methodTarget && methodTarget !== methodTest.id) {
          // User specified a single test method to run, so skip all others
          return;
        }
        run.enqueued(methodTest);
      });
    });

    const firstClassTestItem = Array.from(mapTestClasses.values())[0];
    const oneUri = firstClassTestItem.ourUri;

    // This will always be true since every test added to the map above required a uri
    if (oneUri) {

      // First, clear out the server-side folder for the classes whose testmethods will be run
      const folder = vscode.workspace.getWorkspaceFolder(oneUri);
      const server = await osAPI.asyncServerForUri(oneUri);
      const serverSpec: IServerSpec = {
        username: server.username,
        password: server.password,
        name: server.serverName,
        webServer: {
          host: server.host,
          port: server.port,
          pathPrefix: server.pathPrefix,
          scheme: server.scheme
        }
      };
      const namespace: string = server.namespace.toUpperCase();
      const responseCspapps = await makeRESTRequest(
        "GET",
        serverSpec,
        { apiVersion: 1, namespace: "%SYS", path: "/cspapps/%SYS" }
      );

      if (!responseCspapps?.data?.result?.content?.includes("/_vscode")) {
        const reply = await vscode.window.showErrorMessage(`A '/_vscode' web application must be configured for the %SYS namespace of server '${serverSpec.name}'. The ${namespace} namespace also requires its ^UnitTestRoot global to point to the '${namespace}/UnitTestRoot' subfolder of that web application's path.`, { modal: true }, 'Use IPM Package', 'Follow Manual Instructions');
        if (reply === 'Follow Manual Instructions') {
          vscode.commands.executeCommand('vscode.open', 'https://docs.intersystems.com/components/csp/docbook/DocBook.UI.Page.cls?KEY=GVSCO_serverflow#GVSCO_serverflow_folderspec');
        } else if (reply === 'Use IPM Package') {
          vscode.commands.executeCommand('vscode.open', 'https://openexchange.intersystems.com/package/vscode-per-namespace-settings');
        }
        run.end();
        return;
      }

      const username: string = (serverSpec.username || 'UnknownUser').toLowerCase();

      // When client-side mode is using 'objectscript.conn.docker-compose the first piece of 'authority' is blank,
      if (authority.startsWith(":")) {
        authority = folder?.name || "";
      } else {
        authority = authority.split(":")[0];
      }

      // Load our support classes if they are not already there and the correct version.
      const thisExtension = vscode.extensions.getExtension(extensionId);
      if (!thisExtension) {
        // Never happens, but needed to satisfy typechecking below
        return;
      }
      const extensionUri = thisExtension.extensionUri;
      const supportClassesDir = extensionUri.with({ path: extensionUri.path + '/serverSide/src' + '/vscode/dc/testingmanager'});
      const expectedVersion = thisExtension.packageJSON.version;
      const expectedCount = (await vscode.workspace.fs.readDirectory(supportClassesDir)).length;
      const response = await makeRESTRequest(
        "POST",
        serverSpec,
        { apiVersion: 1, namespace, path: "/action/query" },
        {
          query: `SELECT parent, _Default FROM %Dictionary.CompiledParameter WHERE Name='VERSION' AND parent %STARTSWITH 'vscode.dc.testingmanager.' AND _Default=?`,
          parameters: [expectedVersion],
        },
      );
      if (response?.status !== 200 || response?.data?.result?.content?.length !== expectedCount) {
        const destinationDir = vscode.Uri.from({ scheme: 'isfs', authority: `${authority}:${namespace}`, path: '/vscode/dc/testingmanager'})
        try {
          await vscode.workspace.fs.copy(supportClassesDir, destinationDir, { overwrite: true });
        } catch (error) {
          await vscode.window.showErrorMessage(`Failed to copy support classes from ${supportClassesDir.path.slice(1)} to ${destinationDir.toString()}\n\n${JSON.stringify(error)}`, {modal: true});
        }
      }

      // Form the ISFS target folder uri and delete any existing content
      // Note that authority here is just server name, no :namespace
      const testRoot = vscode.Uri.from({ scheme: 'isfs', authority, path: `/_vscode/${namespace}/UnitTestRoot/${username}`, query: "csp&ns=%SYS" });
      try {
        // Limitation of the Atelier API means this can only delete the files, not the folders
        // but zombie folders shouldn't cause problems.
        await vscode.workspace.fs.delete(testRoot, { recursive: true });
      } catch (error) {
        console.log(error);
      }

      // Map of uri strings checked for presence of a coverage.list file, recording the absolute path of those that were found
      const mapCoverageLists = new Map<string, string>();
      for await (const mapInstance of mapTestClasses) {
        const key = mapInstance[0];
        const pathParts = key.split('/');
        pathParts.pop();
        const sourceBaseUri = mapInstance[1].ourUri?.with({ path: mapInstance[1].ourUri.path.split('/').slice(0, -pathParts.length).join('/') });
        if (!sourceBaseUri) {
          console.log(`No sourceBaseUri for key=${key}`);
          continue;
        }
        // isfs folders can't supply coverage.list files, so don't bother looking.
        // Instead the file has to be put in the /namespace/UnitTestRoot/ folder of the /_vscode webapp of the %SYS namespace.
        if (['isfs', 'isfs-readonly'].includes(sourceBaseUri.scheme)) {
          continue;
        }
        while (pathParts.length > 0) {
          const currentPath = pathParts.join('/');
          // Check for coverage.list file here
          const coverageListUri = sourceBaseUri.with({ path: sourceBaseUri.path.concat(`${currentPath}/coverage.list`) });
          if (mapCoverageLists.has(coverageListUri.toString())) {
            // Already checked this uri path, and therefore all its ancestors
            break;
          }
          try {
            await vscode.workspace.fs.stat(coverageListUri);
            mapCoverageLists.set(coverageListUri.toString(), testRoot.path.concat(currentPath));
          } catch (error) {
            if (error.code !== vscode.FileSystemError.FileNotFound().code) {
              console.log(`Error checking for ${coverageListUri.toString()}:`, error);
            }
            mapCoverageLists.set(coverageListUri.toString(), '');
          }
          pathParts.pop();
        }
      }
      // Copy all coverage.list files found into the corresponding place under testRoot
      for await (const [uriString, path] of mapCoverageLists) {
        if (path.length > 0) {
          const coverageListUri = vscode.Uri.parse(uriString, true);
          try {
            await vscode.workspace.fs.copy(coverageListUri, testRoot.with({ path: `${path}/coverage.list` }));
          } catch (error) {
            console.log(`Error copying ${coverageListUri.path}:`, error);
          }
        }
      }

      // Next, copy the classes into the folder as a package hierarchy
      for await (const mapInstance of mapTestClasses) {
        const key = mapInstance[0];
        const classTest = mapInstance[1];
        const uri = classTest.uri;
        const keyParts = key.split('/');
        const clsFile = keyParts.pop() || '';
        const directoryUri = testRoot.with({ path: testRoot.path.concat(keyParts.join('/') + '/') });
        // This will always be true since every test added to the map above required a uri
        if (uri) {
          try {
            await vscode.workspace.fs.copy(uri, directoryUri.with({ path: directoryUri.path.concat(clsFile) }));
          } catch (error) {
            console.log(error);
            run.errored(classTest, new vscode.TestMessage(error instanceof Error ? error.message : String(error)));
            continue;
          }
        }
      }

      // Finally, run the tests using the debugger API
      // but only stop at breakpoints etc if user chose "Debug Test" instead of "Run Test"
      const isClientSideMode = controller.id === `${extensionId}-Local`;
      const isDebug = request.profile?.kind === vscode.TestRunProfileKind.Debug;
      const runQualifiers = !isClientSideMode ? "/noload/nodelete" : isDebug ? "/noload" : "";
      const userParam = vscode.workspace.getConfiguration('objectscript', oneUri).get<boolean>('multilineMethodArgs', false) ? 1 : 0;
      const runIndex = allTestRuns.push(run) - 1;
      runIndices.push(runIndex);

      // Compute the testspec argument for %UnitTest.Manager.RunTest() call.
      // Typically it is a testsuite, the subfolder where we copied all the testclasses,
      // but if only a single method of a single class is being tested we will also specify testcase and testmethod.
      let testSpec = username;
      if (request.include?.length === 1) {
        const idParts = request.include[0].id.split(":");
        if (idParts.length === 5) {
          testSpec = `${username}\\${idParts[3].split(".").slice(0, -1).join("\\")}:${idParts[3]}:${idParts[4]}`;
        }
      }

      let program = `##class(vscode.dc.testingmanager.StandardManager).RunTest("${testSpec}","${runQualifiers}",${userParam})`;
      if (coverageRequest) {
        program = `##class(vscode.dc.testingmanager.CoverageManager).RunTest("${testSpec}","${runQualifiers}",${userParam})`
        request.profile.loadDetailedCoverage = async (_testRun, fileCoverage, _token) => {
          return fileCoverage instanceof OurFileCoverage ? fileCoverage.loadDetailedCoverage() : [];
        };
        request.profile.loadDetailedCoverageForTest = async (_testRun, fileCoverage, fromTestItem, _token) => {
          return fileCoverage instanceof OurFileCoverage ? fileCoverage.loadDetailedCoverage(fromTestItem) : [];
        };
      }

      const configuration = {
        type: "objectscript",
        request: "launch",
        name: `${controller.id.split("-").pop()}Tests:${serverSpec.name}:${namespace}:${username}`,
        program,

        // Extra properties needed by our DebugAdapterTracker
        testingRunIndex: runIndex,
        testingIdBase: firstClassTestItem.id.split(":", 3).join(":")
      };
      const sessionOptions: vscode.DebugSessionOptions = {
        noDebug: !isDebug,
        suppressDebugToolbar: request.profile?.kind !== vscode.TestRunProfileKind.Debug,
        suppressDebugView: request.profile?.kind !== vscode.TestRunProfileKind.Debug,
        testRun: run,
      };

      // ObjectScript debugger's initializeRequest handler needs to identify target server and namespace
      // and does this from current active document, so here we make sure there's a suitable one.
      vscode.commands.executeCommand("vscode.open", oneUri, { preserveFocus: true });

      // When debugging in client-side mode the classes must be loaded and compiled before the debug run happens, otherwise breakpoints don't bind
      if (isClientSideMode && isDebug && !cancellation.isCancellationRequested) {

        // Without the /debug option the classes are compiled without maps, preventing breakpoints from binding.
        const preloadConfig = {
          "type": "objectscript",
          "request": "launch",
          "name": 'LocalTests.Preload',
          "program": `##class(%UnitTest.Manager).RunTest("${testSpec}","/nodisplay/load/debug/norun/nodelete")`,
        };

        // Prepare to detect when the preload completes
        let sessionTerminated: () => void;
        const listener = vscode.debug.onDidTerminateDebugSession((session) => {
          if (session.name === 'LocalTests.Preload') {
            sessionTerminated();
          }
        });
        const sessionTerminatedPromise = new Promise<void>(resolve => sessionTerminated = resolve);

        // Start the preload
        if (!await vscode.debug.startDebugging(folder, preloadConfig, { noDebug: true, suppressDebugStatusbar: true })) {
          listener.dispose();
          await vscode.window.showErrorMessage(`Failed to preload client-side test classes for debugging`, { modal: true });
          run.end();
          allTestRuns[runIndex] = undefined;
          return;
        };

        // Wait for it to complete
        await sessionTerminatedPromise;
        listener.dispose();
      }

      // Start the run unless already cancelled
      if (cancellation.isCancellationRequested || !await vscode.debug.startDebugging(folder, configuration, sessionOptions)) {
        if (!cancellation.isCancellationRequested) {
          await vscode.window.showErrorMessage(`Failed to launch testing`, { modal: true });
        }
        run.end();
        allTestRuns[runIndex] = undefined;
        return;
      }
    }
  }
}

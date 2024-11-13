"use strict";

import * as vscode from "vscode";
import * as serverManager from "@intersystems-community/intersystems-servermanager";
import { setupHistoryExplorerController } from "./historyExplorer";
import { setupServerTestsController } from "./serverTests";
import { setupLocalTestsController } from "./localTests";
import { DebugTrackerFactory } from "./debugTrackerFactory";

export const extensionId = "intersystems-community.testingmanager";
export let localTestController: vscode.TestController;
export let loadedTestController: vscode.TestController;
export let historyBrowserController: vscode.TestController;
export let osAPI: any;
export let smAPI: serverManager.ServerManagerAPI | undefined;

export interface TestRun extends vscode.TestRun {
  debugSession?: vscode.DebugSession
}
export const allTestRuns: (TestRun | undefined)[] = [];

async function getServerManagerAPI(): Promise<serverManager.ServerManagerAPI | undefined> {
    const targetExtension = vscode.extensions.getExtension("intersystems-community.servermanager");
    if (!targetExtension) {
      return undefined;
    }
    if (!targetExtension.isActive) {
      await targetExtension.activate();
    }
    const api = targetExtension.exports;

    if (!api) {
      return undefined;
    }
    return api;
  }

async function getObjectScriptAPI(): Promise<any> {
    const targetExtension = vscode.extensions.getExtension("intersystems-community.vscode-objectscript");
    if (!targetExtension) {
      return undefined;
    }
    if (!targetExtension.isActive) {
      await targetExtension.activate();
    }
    const api = targetExtension.exports;

    if (!api) {
      return undefined;
    }
    return api;
  }

export async function activate(context: vscode.ExtensionContext) {

    osAPI = await getObjectScriptAPI();
    smAPI = await getServerManagerAPI();
    // TODO notify user if either of these returned undefined (extensionDependencies setting should prevent that, but better to be safe)

    // Other parts of this extension will use the test controllers we create here
    localTestController = vscode.tests.createTestController(`${extensionId}-Local`, '$(folder-library) Local Tests');
    context.subscriptions.push(localTestController);
    context.subscriptions.push(await setupLocalTestsController());

    loadedTestController = vscode.tests.createTestController(`${extensionId}-Loaded`, '$(server-environment) Server Tests');
    context.subscriptions.push(loadedTestController);
    await setupServerTestsController();

    historyBrowserController = vscode.tests.createTestController(`${extensionId}-History`, 'Recent History');
    context.subscriptions.push(historyBrowserController);
    await setupHistoryExplorerController();

    context.subscriptions.push(
      vscode.debug.registerDebugAdapterTrackerFactory('objectscript', new DebugTrackerFactory())
    );

    // Register the commands
    context.subscriptions.push(
        //DUMMY example (remember to add entries to `contributes.commands` in package.json)
        //vscode.commands.registerCommand(`${extensionId}.templateCommand`, () => {}),
    );

    // Listen for relevant configuration changes
    context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
        // TODO
    }));

    // Expose our API (if any)
    const api = {
    };

    // 'export' our public api-surface
    return api;
}

export function deactivate() {
    //
}

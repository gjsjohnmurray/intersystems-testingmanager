import axios, { AxiosResponse } from "axios";
import * as vscode from "vscode";
import { IServerSpec } from "@intersystems-community/intersystems-servermanager";
import { smAPI } from "./extension";
import * as https from 'https';

const AUTHENTICATION_PROVIDER = "intersystems-server-credentials";

export interface IServerSession {
	serverName: string;
	username: string;
	cookies: string[];
}

export const serverSessions = new Map<string, IServerSession>();

export interface IAtelierRESTEndpoint {
    apiVersion: number;
    namespace: string;
    path: string;
}

function updateCookies(oldCookies: string[], newCookies: string[]): string[] {
	newCookies.forEach((cookie) => {
		const [cookieName] = cookie.split("=");
		const index = oldCookies.findIndex((el) => el.startsWith(cookieName));
		if (index >= 0) {
			oldCookies[index] = cookie;
		} else {
			oldCookies.push(cookie);
		}
	});
	return oldCookies;
}

function getCookies(server: IServerSpec): string[] {
	return serverSessions.get(server.name)?.cookies ?? [];
}

/**
 * Make a REST request to an InterSystems server.
 *
 * @param method The REST method.
 * @param server The server to send the request to.
 * @param endpoint Optional endpoint object. If omitted the request will be to /api/atelier/
 * @param data Optional request data. Usually passed for POST requests.
 */
export async function makeRESTRequest(
    method: "HEAD"|"GET"|"POST",
    server: IServerSpec,
    endpoint?: IAtelierRESTEndpoint,
    data?: any,
    ): Promise<AxiosResponse | undefined> {

    // Create the HTTPS agent
    const httpsAgent = new https.Agent({ rejectUnauthorized: vscode.workspace.getConfiguration("http").get("proxyStrictSSL") });

    // Get the cookies
    let cookies: string[] = getCookies(server);

    // Build the URL
    let url = server.webServer.scheme + "://" + server.webServer.host + ":" + String(server.webServer.port);
    const pathPrefix = server.webServer.pathPrefix;
    if (pathPrefix && pathPrefix !== "") {
        url += pathPrefix;
    }
    url += "/api/atelier/";
    if (endpoint) {
        url += "v" + String(endpoint.apiVersion) + "/" + endpoint.namespace + endpoint.path;
    }

    // Make the request (SASchema support removed)
    try {
        let respdata: AxiosResponse;
        if (data !== undefined) {
            // There is a data payload
            respdata = await axios.request(
                {
                    httpsAgent,
                    data,
                    headers: {
                        "Content-Type": "application/json",
            						"Cookie": cookies.join(" ")
                    },
                    method,
                    url: encodeURI(url),
                    validateStatus: (status) => {
                        return status < 500;
                    },
                    withCredentials: true,
                },
            );
            if (respdata.status === 401) {
                // Use AuthenticationProvider to get password if not supplied by caller
                await resolveCredentials(server);
                if (typeof server.username !== "undefined" && typeof server.password !== "undefined") {
                    // Either we had no cookies or they expired, so resend the request with basic auth
                    respdata = await axios.request(
                        {
                            httpsAgent,
                            auth: {
                                password: server.password,
                                username: server.username,
                            },
                            data,
                            headers: {
                                "Content-Type": "application/json",
                            },
                            method,
                            url: encodeURI(url),
                            withCredentials: true,
                        },
                    );
                }
            }
        } else {
            // No data payload
            respdata = await axios.request(
                {
                    httpsAgent,
                    method,
                    headers: {
                      "Cookie": cookies.join(" ")
                    },
                    url: encodeURI(url),
                    validateStatus: (status) => {
                        return status < 500;
                    },
                    withCredentials: true,
                },
            );
            if (respdata.status === 401) {
                // Use AuthenticationProvider to get password if not supplied by caller
                await resolveCredentials(server);
                if (typeof server.username !== "undefined" && typeof server.password !== "undefined") {
                    // Either we had no cookies or they expired, so resend the request with basic auth
                    respdata = await axios.request(
                        {
                            httpsAgent,
                            auth: {
                                password: server.password,
                                username: server.username,
                            },
                            method,
                            url: encodeURI(url),
                            withCredentials: true,
                        },
                    );
                }
            }
        }

        cookies = updateCookies(cookies, respdata.headers['set-cookie'] || []);

        // Only store the session for a serverName the first time because subsequent requests
        // to a server with no username defined must not lose initially-recorded username
        const session = serverSessions.get(server.name);
        if (!session) {
          serverSessions.set(server.name, { serverName: server.name, username: server.username || '', cookies });
        } else {
          serverSessions.set(server.name, { ...session, cookies });
        }
        return respdata;
    } catch (error) {
        console.log(error);
        return undefined;
    }
}

/**
 * Attempt to log out of our session on an InterSystems server.
 *
 * @param serverName The name of the server to send the request to.
 */
export async function logout(serverName: string) {

  if (!smAPI) {
    return;
  }

	const server = await smAPI.getServerSpec(serverName, undefined);

	if (!server) {
		return;
	}

	// Create the HTTPS agent if in a node environment
	const httpsAgent = typeof https.Agent == "function" ? new https.Agent({ rejectUnauthorized: vscode.workspace.getConfiguration("http").get("proxyStrictSSL") }) : undefined;

	// Get the cookies
	let cookies: string[] = getCookies(server);

	// Build the URL
	let url = server.webServer.scheme + "://" + server.webServer.host + ":" + String(server.webServer.port);
	const pathPrefix = server.webServer.pathPrefix;
	if (pathPrefix && pathPrefix !== "") {
		url += pathPrefix;
	}
	url += "/api/atelier/?CacheLogout=end";

	// Make the request but don't do anything with the response or any errors
	try {
		await axios.request(
			{
				httpsAgent,
				method: "HEAD",
				headers: {
					"Cookie": cookies.join(" ")
				},
				url: encodeURI(url),
				validateStatus: (status) => {
					return status < 500;
				},
				withCredentials: true,
			},
		);
	} catch { }
}

export async function resolveCredentials(serverSpec: IServerSpec) {
    if (typeof serverSpec.password === "undefined" && smAPI) {
        const scopes = [serverSpec.name, serverSpec.username || ""];

        // Handle Server Manager extension version < 3.8.0
        const account = smAPI.getAccount ? smAPI.getAccount(serverSpec) : undefined;
        let session = await vscode.authentication.getSession(
            AUTHENTICATION_PROVIDER,
            scopes,
            { silent: true, account },
        );
        if (!session) {
            session = await vscode.authentication.getSession(
                AUTHENTICATION_PROVIDER,
                scopes,
                { createIfNone: true, account },
            );
        }
        if (session) {
            serverSpec.username = session.scopes[1] === "unknownuser" ? "" : session.scopes[1];
            serverSpec.password = session.accessToken;
        }
    }
}

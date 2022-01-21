import axios, { AxiosResponse } from "axios";
import axiosCookieJarSupport from "axios-cookiejar-support";
import tough = require("tough-cookie");
import * as vscode from "vscode";
import { IServerSpec } from "./extension";

const AUTHENTICATION_PROVIDER = "intersystems-server-credentials";

axiosCookieJarSupport(axios);

/**
 * Cookie jar for REST requests to InterSystems servers.
 */
export const cookieJar: tough.CookieJar = new tough.CookieJar();

export interface IAtelierRESTEndpoint {
    apiVersion: number;
    namespace: string;
    path: string;
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
                    data,
                    headers: {
                        "Content-Type": "application/json",
                    },
                    jar: cookieJar,
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
                            auth: {
                                password: server.password,
                                username: server.username,
                            },
                            data,
                            headers: {
                                "Content-Type": "application/json",
                            },
                            jar: cookieJar,
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
                    jar: cookieJar,
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
                            auth: {
                                password: server.password,
                                username: server.username,
                            },
                            jar: cookieJar,
                            method,
                            url: encodeURI(url),
                            withCredentials: true,
                        },
                    );
                }
            }
        }
        return respdata;
    } catch (error) {
        console.log(error);
        return undefined;
    }
}

export async function resolveCredentials(serverSpec: IServerSpec) {
    // This arises if setting says to use authentication provider
    if (typeof serverSpec.password === "undefined") {
        const scopes = [serverSpec.name, serverSpec.username || ""];
        let session = await vscode.authentication.getSession(
            AUTHENTICATION_PROVIDER,
            scopes,
            { silent: true },
        );
        if (!session) {
            session = await vscode.authentication.getSession(
                AUTHENTICATION_PROVIDER,
                scopes,
                { createIfNone: true },
            );
        }
        if (session) {
            serverSpec.username = session.scopes[1] === "UnknownUser" ? "" : session.scopes[1];
            serverSpec.password = session.accessToken;
        }
    }
}

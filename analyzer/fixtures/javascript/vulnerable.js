import axios from "axios";
import child_process from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import libxmljs from "libxmljs";
import serialize from "node-serialize";

export function evaluate(request) {
  const code = `(${request.query.expression})`;
  return eval(code);
}

export function runCommand(request) {
  const command = "printf " + request.body.message;
  return child_process.exec(command);
}

export function parseUnsafeXml(xmlDocument) {
  return libxmljs.parseXml(xmlDocument, { noent: true });
}

export async function fetchUserUrl(request) {
  const targetUrl = `http://${request.params.host}/health`;
  return axios.get(targetUrl);
}

export function exposeFile(reportPath) {
  fs.chmodSync(reportPath, 0o666);
}

export function weakHash(payload) {
  return crypto.createHash("md5").update(payload).digest("hex");
}

export function hardcodedCredential() {
  const databasePassword = "prod-secret-12345";
  return databasePassword;
}

export function shortKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 1536 });
}

export function predictableToken() {
  const authToken = Math.random();
  return authToken;
}

export function insecureTlsRequest() {
  return https.request({
    hostname: "api.example.invalid",
    rejectUnauthorized: false,
  });
}

export function insecureCookie(response) {
  response.cookie("session", "value", {
    httpOnly: true,
    secure: true,
    maxAge: 86400000,
  });
}

// api_key = "development-secret!@#$%^&*()"
export function leakedCommentMarker() {
  return "comment above contains a credential";
}

export function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export function spinForever() {
  while (true) {
    console.log("still running");
  }
}

export function exposeFailure(response, error) {
  response.send(error.stack);
}

export function ignoreFailure() {
  try {
    throw new Error("failure");
  } catch (error) {
  }
}

export function deserialize(payload) {
  return serialize.unserialize(payload);
}

export function leftOverDebugger() {
  debugger;
}

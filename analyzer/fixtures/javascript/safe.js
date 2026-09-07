import child_process from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";

export function evaluateFixedCode() {
  const trustedCode = "40 + 2";
  return eval(trustedCode);
}

export function fixedCalculation(left, right) {
  return Number(left) + Number(right);
}

export function fixedCommand() {
  const trustedCommand = "printf '%s' hello";
  return child_process.exec(trustedCommand);
}

export async function fetchAllowlistedService() {
  const trustedUrl = "https://api.example.invalid/health";
  return fetch(trustedUrl);
}

export function protectFile(reportPath) {
  fs.chmodSync(reportPath, 0o600);
}

export function strongHash(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

export function configuredCredential() {
  return process.env.DATABASE_PASSWORD;
}

export function strongKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
}

export function secureToken() {
  return crypto.randomBytes(32).toString("hex");
}

export function secureTlsRequest() {
  return https.request({
    hostname: "api.example.invalid",
    rejectUnauthorized: true,
  });
}

export function secureCookie(response) {
  response.cookie("session", "value", {
    httpOnly: true,
    secure: true,
    maxAge: 0,
  });
}

export function saltedPasswordHash(password, salt) {
  return crypto.scryptSync(password, salt, 64);
}

export function boundedWork() {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    console.log(attempt);
  }
}

export function loopWithBreak() {
  while (true) {
    break;
  }
}

export function loopWithReturn() {
  while (true) {
    return;
  }
}

export function genericFailure(response) {
  response.status(500).send("request failed");
}

export function handleFailure() {
  try {
    throw new TypeError("failure");
  } catch (error) {
    console.error("operation failed");
  }
}

export function parseJson(payload) {
  return JSON.parse(payload);
}

export function useApplicationDeserializer(serializer, payload) {
  return serializer.unserialize(payload);
}

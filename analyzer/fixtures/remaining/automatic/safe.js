const crypto = require("node:crypto")

function installPackage(payload, publicKey, signature) {
  const verified = crypto.verify("sha256", payload, publicKey, signature)
  if (!verified) {
    throw new Error("package signature verification failed")
  }
  return loadPackage(payload)
}

function loadPackage(payload) {
  return payload.length
}

function readInitializedToken() {
  const token = "ready"
  return token.length
}

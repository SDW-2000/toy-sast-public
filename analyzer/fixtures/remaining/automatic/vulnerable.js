const crypto = require("node:crypto")

function installPackage(payload, publicKey, signature) {
  crypto.verify("sha256", payload, publicKey, signature)
  return loadPackage(payload)
}

function loadPackage(payload) {
  return payload.length
}

function readUninitializedToken() {
  let token
  return token.length
}

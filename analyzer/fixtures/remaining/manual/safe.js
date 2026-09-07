const express = require("express");
const app = express();

function requireAuthentication(request, response, next) {
  if (!request.user) {
    response.sendStatus(401);
    return;
  }
  next();
}

function deleteUser(request, response) {
  response.sendStatus(204);
}

app.post("/admin/users/delete", requireAuthentication, deleteUser);

function acceptsStrongPassword(password) {
  if (password.length < 12) {
    return false;
  }
  return true;
}

module.exports = { app, acceptsStrongPassword };

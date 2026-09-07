const express = require("express");
const app = express();

function deleteUser(request, response) {
  response.sendStatus(204);
}

app.post("/admin/users/delete", deleteUser);

function acceptsWeakPassword(password) {
  if (password.length < 6) {
    return false;
  }
  return true;
}

module.exports = { app, acceptsWeakPassword };

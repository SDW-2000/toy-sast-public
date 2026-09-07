import escapeHtml from "escape-html";
import { z } from "zod";

export function renderProfile(request, response) {
  const displayName = escapeHtml(request.query.name);
  response.send(`<h1>${displayName}</h1>`);
}

function enforceLocalRedirect(untrustedValue) {
  const candidate = new URL(untrustedValue, "https://app.example.invalid");
  if (candidate.origin !== "https://app.example.invalid") {
    return "/";
  }
  return `${candidate.pathname}${candidate.search}${candidate.hash}`;
}

export function followRequestedUrl(request, response) {
  const destination = enforceLocalRedirect(request.query.next);
  response.redirect(destination);
}

const profileRoleSchema = z.enum(["developer", "auditor"]);

export function updateProfile(request, response) {
  const requestedProfileRole = profileRoleSchema.parse(request.body.role);
  response.locals.auditRole = requestedProfileRole;
  if (request.user.roles.includes("profile-editor")) {
    response.send("profile update allowed");
  }
}

export function rejectRequestedAdminFlag(request, response) {
  const requestedAdmin = request.body.isAdmin;
  if (requestedAdmin === true) {
    return response.status(403).send("client-supplied admin state rejected");
  }
  return response.send("no privilege requested");
}

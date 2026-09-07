export function renderProfile(request, response) {
  const displayName = request.query.name;
  response.send(`<h1>${displayName}</h1>`);
}

export function followRequestedUrl(request, response) {
  const destination = request.query.next;
  response.redirect(destination);
}

export function trustRequestedAdminFlag(request, response) {
  request.user.isAdmin = request.body.isAdmin;
  response.send("authorization state updated");
}

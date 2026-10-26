var H = Hooks;

function unrelatedOwner() {
  const otherRef = (0, H.useRef)(null);
  return otherRef;
}

export function Panel() {
  const anchorRef = (0, H.useRef)(null);
  const actionRunner = (0, H.useActionRunner)();

  registerAnchor(anchorRef);
  return actionRunner.render();
}

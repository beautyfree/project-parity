export function choose(flag, first, second) {
  let selected;
  if (flag) {
    selected = first;
  } else {
    selected = second;
  }
  return selected;
}

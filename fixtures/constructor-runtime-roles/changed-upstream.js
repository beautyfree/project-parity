// Three nearby, real constructor divergences remain observable.
export class SwappedPair {
  constructor(a, b) { this.left = b; this.right = a; }
  consume() { return [this.left, this.right]; }
}
export class MissingPair {
  constructor(a, b) { this.left = a; }
  consume() { return [this.left, this.right]; }
}
export class ReorderedWrites {
  constructor(a, b) { this.right = b; this.left = a; }
  consume() { return [this.left, this.right]; }
}

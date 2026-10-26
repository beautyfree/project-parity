export class ParameterPair {
  constructor(a, b) { this.left = a; this.right = b; }
  consume() { return [this.left, this.right]; }
}
export class RenamedPair {
  constructor(valueA, valueB) { this.left = valueA; this.right = valueB; }
  consume() { return [this.left, this.right]; }
}
export class DiscardingConstructor {
  constructor(a, b) {}
  consume() { return [this.left, this.right]; }
}
export class EmptyConstructor {
  constructor(a, b) {}
}
export class OrdinaryOwner {
  empty(a, b) {}
}
export class XmlHooks {
  onOpenTag(a, b) {}
  onCloseTag(a, b) {}
}

// Empty TS bodies can still perform observable constructor writes.
export class ParameterPair {
  constructor(public left: unknown, public right: unknown) {}
  consume() { return [this.left, this.right]; }
}

// Type-only annotations must not create a behavioral difference.
export class TypedPair {
  left: unknown;
  right: unknown;
  constructor(first: unknown, second: unknown) {
    this.left = first;
    this.right = second;
  }
  consume() { return [this.left, this.right]; }
}

// Parameter-property spelling is an observable runtime property key.
export class DifferentFields {
  constructor(public first: unknown, public second: unknown) {}
  consume() { return [this.first, this.second]; }
}

export class EmptyConstructor {
  constructor(first: unknown, second: unknown) {}
}
export class OrdinaryOwner {
  empty(first: unknown, second: unknown) {}
}
export class XmlHooks {
  onOpenTag(name: unknown, attributes: unknown) {}
  onCloseTag(name: unknown, namespace: unknown) {}
}

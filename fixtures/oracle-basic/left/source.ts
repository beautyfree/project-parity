export function renamedOwner(value: number) {
  return value + 1
}

export function wrappedOwner(value: string) {
  return client.save(value.trim())
}

export function subtractOwner(left: number, right: number) {
  return left - right
}

export function changedApiOwner(value: string) {
  return client.save(value)
}

export function changedLiteralOwner(value: string) {
  return waitFor(value, 1000)
}

export function createMenuManager<T>(items: T[]) {
  const active = new Set<T>()
  for (const item of items) active.add(item)
  return {
    has(item: T) {
      return active.has(item)
    },
    destroy() {
      active.clear()
    },
  }
}

import { useRef } from 'react'

export function Panel() {
  const anchorRef = useRef<HTMLDivElement>(null)
  const actionRunner = useActionRunner()

  registerAnchor(anchorRef)
  return actionRunner.render()
}

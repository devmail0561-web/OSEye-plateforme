import { useRef, useEffect, type RefObject, type DependencyList } from 'react'
import * as d3 from 'd3'

export function useD3<T extends SVGElement>(
  renderFn: (selection: d3.Selection<T, unknown, null, undefined>) => (() => void) | void,
  deps: DependencyList,
): RefObject<T> {
  const ref = useRef<T>(null)

  useEffect(() => {
    if (!ref.current) return
    const selection = d3.select(ref.current) as d3.Selection<T, unknown, null, undefined>
    const cleanup = renderFn(selection)
    return cleanup ?? undefined
  }, deps) // eslint-disable-line react-hooks/exhaustive-deps

  return ref
}

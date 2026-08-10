import { useRef, useEffect } from 'react'
import { EditorView, basicSetup } from 'codemirror'
import { EditorState, Compartment } from '@codemirror/state'
import { yaml } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'

// codemirror is loaded via bare import — no @codemirror/view re-export needed

interface Props {
  value: string
  onChange?: (value: string) => void
  readOnly?: boolean
  dark?: boolean
}

export default function CodeEditor({ value, onChange, readOnly = false, dark = true }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const themeCompartment = useRef(new Compartment())

  useEffect(() => {
    if (!containerRef.current) return

    const updateListener = EditorView.updateListener.of((update) => {
      if (update.docChanged) {
        onChange?.(update.state.doc.toString())
      }
    })

    const state = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        yaml(),
        themeCompartment.current.of(dark ? oneDark : []),
        EditorState.readOnly.of(readOnly),
        updateListener,
        EditorView.theme({
          '&': { height: '100%' },
          '.cm-scroller': { fontFamily: 'monospace', fontSize: '13px' },
        }),
      ],
    })

    viewRef.current = new EditorView({ state, parent: containerRef.current })

    return () => {
      viewRef.current?.destroy()
      viewRef.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Sync dark/light theme
  useEffect(() => {
    if (!viewRef.current) return
    viewRef.current.dispatch({
      effects: themeCompartment.current.reconfigure(dark ? oneDark : []),
    })
  }, [dark])

  // Sync value if changed externally
  useEffect(() => {
    if (!viewRef.current) return
    const current = viewRef.current.state.doc.toString()
    if (current !== value) {
      viewRef.current.dispatch({
        changes: { from: 0, to: current.length, insert: value },
      })
    }
  }, [value])

  return <div ref={containerRef} className="h-full rounded border border-gray-300 dark:border-gray-700 overflow-hidden" />
}

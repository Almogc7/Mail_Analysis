import { useState } from 'react'

/** Copies text to the clipboard and says whether it worked. The text is never rendered as markup and never becomes a link. */
export function CopyButton({ text, label, title }: { text: string; label: string; title?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      setState('failed')
    }
  }

  return (
    <>
      <button type="button" onClick={copy} title={title}>
        {label}
      </button>
      {state !== 'idle' && (
        <span className="wb-copy-state" role="status">
          {state === 'copied' ? 'Copied' : 'Copy failed'}
        </span>
      )}
    </>
  )
}

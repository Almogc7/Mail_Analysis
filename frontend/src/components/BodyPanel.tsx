import { useState } from 'react'
import type { BodyInfo } from '../types'

/**
 * The message body as PLAIN TEXT, collapsed by default. HTML is never rendered: only the text part is shown, and a message with
 * only an HTML part says so instead of showing markup. The text lives in the live response only (D5): it is not stored, logged or exported.
 */
export function BodyPanel({ body, text }: { body: BodyInfo; text: string | null }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="view-card wb-panel" aria-label="Body">
      <h2 className="wb-title">Body</h2>
      <table className="wb-table">
        <tbody>
          <tr><th scope="row">Language</th><td>{body.language ?? 'not detected'}{body.language_status ? ` (${body.language_status.replaceAll('_', ' ')})` : ''}</td></tr>
          <tr><th scope="row">Size</th><td>{body.text_chars} characters of text{body.has_html ? `, ${body.html_chars} of HTML` : ', no HTML part'}</td></tr>
          <tr><th scope="row">Links</th><td>{body.links}</td></tr>
          <tr><th scope="row">Forms</th><td>{body.forms}</td></tr>
          <tr><th scope="row">Remote images</th><td>{body.remote_images}</td></tr>
        </tbody>
      </table>
      <p className="wb-note">
        Shown as plain text only. HTML is never rendered and remote images are never loaded. This text is kept in memory for a short time and is not
        stored, logged or exported.
      </p>
      <button type="button" className="wb-toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {open ? 'Hide body text' : 'Show body text'}
      </button>
      {open &&
        (text ? (
          <pre className="wb-pre wb-pre--text" tabIndex={0} aria-label="Body text" dir="auto">{text}</pre>
        ) : (
          <p className="wb-note">{body.has_html ? 'This message has only an HTML part. It is not rendered here.' : 'This message has no body text.'}</p>
        ))}
    </section>
  )
}

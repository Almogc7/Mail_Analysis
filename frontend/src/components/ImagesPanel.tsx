import type { ImageEntry } from '../types'

/** A list about images, never the images: nothing here loads or draws one, so a tracking pixel cannot fire. */
export function ImagesPanel({ images }: { images: ImageEntry[] }) {
  return (
    <section className="view-card wb-panel" aria-label="Images">
      <h2 className="wb-title">Images ({images.length})</h2>
      <p className="wb-lead">Listed, not shown. QR codes in images are not decoded yet, so a QR code in an image would not be noticed.</p>
      {images.length === 0 ? (
        <p className="wb-note">No images found.</p>
      ) : (
        <ul className="wb-list">
          {images.map((img, i) => (
            <li key={i} className="wb-row">
              <div className="wb-row-main">
                <span className="wb-badge">{img.source === 'html' ? 'remote image in the HTML' : 'attached image'}</span>
                <span className="wb-mono">{img.url_defanged ?? img.filename ?? '(unnamed)'}</span>
              </div>
              <div className="wb-small">
                {[img.host ? `host ${img.host}` : null, img.size_bytes !== null ? `${img.size_bytes} bytes` : null, img.decoded === null ? 'not decoded' : `${img.decoded.length} code(s) decoded`]
                  .filter(Boolean)
                  .join(' · ')}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

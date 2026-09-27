import { useState } from 'react'

export function EnrichmentRawData({ rawData }: { rawData: Record<string, unknown> }) {
  const [expandedIoc, setExpandedIoc] = useState<string | null>(null)
  const iocs = Object.entries(rawData)

  if (iocs.length === 0) return null

  return (
    <div className="enrichment-raw-data">
      <p className="raw-data-heading">Raw provider data ({iocs.length} IOC(s))</p>
      {iocs.map(([ioc, data]) => (
        <div className="raw-data-ioc" key={ioc}>
          <button
            className="raw-data-toggle"
            onClick={() => setExpandedIoc((cur) => (cur === ioc ? null : ioc))}
            aria-expanded={expandedIoc === ioc}
          >
            <span className="expand-caret">{expandedIoc === ioc ? '▾' : '▸'}</span>
            <code>{ioc}</code>
          </button>
          {expandedIoc === ioc && <pre className="raw-data-json">{JSON.stringify(data, null, 2)}</pre>}
        </div>
      ))}
    </div>
  )
}

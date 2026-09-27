import { useRef, useState } from 'react'

interface UploadViewProps {
  onSubmit: (file: File) => void
  submitting: boolean
  submitError: string | null
}

const ALLOWED_EXTENSIONS = ['.eml', '.msg']

function isAllowedFile(file: File): boolean {
  const name = file.name.toLowerCase()
  return ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext))
}

export function UploadView({ onSubmit, submitting, submitError }: UploadViewProps) {
  const [file, setFile] = useState<File | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0] ?? null
    if (selected && !isAllowedFile(selected)) {
      setValidationError('File must be a .eml or .msg file')
      setFile(null)
      return
    }
    setValidationError(null)
    setFile(selected)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) {
      setValidationError('Choose a .eml or .msg file first')
      return
    }
    onSubmit(file)
  }

  return (
    <div className="view-card upload-view">
      <h1>Mail Analysis</h1>
      <p className="subtitle">Upload a suspicious email (.eml or .msg) for triage.</p>
      <form onSubmit={handleSubmit}>
        <input
          ref={inputRef}
          type="file"
          accept=".eml,.msg"
          onChange={handleFileChange}
          disabled={submitting}
        />
        {file && <p className="file-name">{file.name}</p>}
        {(validationError || submitError) && (
          <p className="error-text">{validationError ?? submitError}</p>
        )}
        <button type="submit" disabled={submitting || !file}>
          {submitting ? 'Submitting…' : 'Analyze'}
        </button>
      </form>
    </div>
  )
}

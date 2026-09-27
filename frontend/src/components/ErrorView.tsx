export function ErrorView({ message, onReset }: { message: string; onReset: () => void }) {
  return (
    <div className="view-card error-view">
      <h2>Analysis failed</h2>
      <p className="error-text">{message}</p>
      <button onClick={onReset}>Try again</button>
    </div>
  )
}

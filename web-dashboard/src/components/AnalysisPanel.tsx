import React, { useState } from 'react'

interface AnalysisPanelProps {
  binary: string
  onResults: (results: any) => void
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ binary, onResults }) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [results, setResults] = useState<any>(null)

  const handleAnalyze = async () => {
    setIsAnalyzing(true)
    try {
      // TODO: Call API to analyze binary
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ binary }),
      })
      const data = await response.json()
      setResults(data)
      onResults(data)
    } catch (error) {
      console.error('Analysis failed:', error)
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <div className="analysis-panel">
      <h3>Binary Analysis</h3>

      <button
        onClick={handleAnalyze}
        disabled={isAnalyzing}
        className="btn-primary"
      >
        {isAnalyzing ? 'Analyzing...' : 'Start Analysis'}
      </button>

      {results && (
        <div className="results">
          <h4>Analysis Results</h4>
          <pre>{JSON.stringify(results, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

export default AnalysisPanel

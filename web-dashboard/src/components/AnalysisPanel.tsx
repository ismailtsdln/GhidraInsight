import React, { useState, useEffect, useRef } from 'react'
import FunctionGraph from './FunctionGraph'
import BinaryDiffViewer from './BinaryDiffViewer'

interface AnalysisPanelProps {
  binary: string
  onResults: (results: any) => void
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ binary, onResults }) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [results, setResults] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'overview' | 'functions' | 'graph' | 'diff'>('overview')
  const [progress, setProgress] = useState<number>(0)
  const [progressMessage, setProgressMessage] = useState<string>('')
  const [searchTerm, setSearchTerm] = useState<string>('')
  const [filterType, setFilterType] = useState<string>('all')
  const wsRef = useRef<WebSocket | null>(null)

  // Filter functions based on search term and filter type
  const getFilteredFunctions = () => {
    if (!results?.functions) return []

    return results.functions.filter((func: any) => {
      const matchesSearch = !searchTerm ||
        (func.name && func.name.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (func.address && func.address.toLowerCase().includes(searchTerm.toLowerCase()))

      const matchesFilter = filterType === 'all' ||
        (filterType === 'high_complexity' && func.complexity > 10) ||
        (filterType === 'large_functions' && func.size > 100) ||
        (filterType === 'entry_points' && func.is_entry_point)

      return matchesSearch && matchesFilter
    })
  }

  useEffect(() => {
    // Connect to WebSocket for real-time updates
    const connectWebSocket = () => {
      const ws = new WebSocket('ws://localhost:8001')

      ws.onopen = () => {
        console.log('WebSocket connected')
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleWebSocketMessage(data)
        } catch (error) {
          console.error('WebSocket message parse error:', error)
        }
      }

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        // Reconnect after delay
        setTimeout(connectWebSocket, 3000)
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    }

    connectWebSocket()

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  const handleWebSocketMessage = (data: any) => {
    switch (data.type) {
      case 'analysis_started':
        setIsAnalyzing(true)
        setProgress(0)
        setProgressMessage(data.message)
        break
      case 'progress':
        setProgress(data.progress)
        setProgressMessage(data.message)
        break
      case 'analysis_complete':
        setIsAnalyzing(false)
        setProgress(100)
        setProgressMessage('Analysis complete')
        setResults(data.result.results)
        onResults(data.result.results)
        break
      case 'error':
        setIsAnalyzing(false)
        setProgressMessage(`Error: ${data.message}`)
        break
    }
  }

  const handleAnalyze = async () => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      alert('WebSocket not connected. Please check server connection.')
      return
    }

    setIsAnalyzing(true)
    setProgress(0)
    setProgressMessage('Connecting...')

    // Send analysis request via WebSocket
    const message = {
      type: 'analyze',
      data: {
        binary_name: binary,
        features: ['basic_info', 'strings', 'entropy']
      }
    }

    wsRef.current.send(JSON.stringify(message))
  }

  const handleExport = (format: 'json' | 'html' | 'pdf') => {
    if (!results) return

    if (format === 'json') {
      const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${binary}-analysis.json`
      a.click()
      URL.revokeObjectURL(url)
    } else if (format === 'html') {
      const html = `
        <html>
          <head><title>${binary} Analysis</title></head>
          <body>
            <h1>${binary} Analysis Report</h1>
            <pre>${JSON.stringify(results, null, 2)}</pre>
          </body>
        </html>
      `
      const blob = new Blob([html], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${binary}-analysis.html`
      a.click()
      URL.revokeObjectURL(url)
    }
    // PDF would require a library like jsPDF
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

      {isAnalyzing && (
        <div className="progress-container">
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <p className="progress-text">{progressMessage}</p>
        </div>
      )}

      {results && (
        <div className="results">
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              Overview
            </button>
            <button
              className={`tab ${activeTab === 'functions' ? 'active' : ''}`}
              onClick={() => setActiveTab('functions')}
            >
              Functions
            </button>
            <button
              className={`tab ${activeTab === 'graph' ? 'active' : ''}`}
              onClick={() => setActiveTab('graph')}
            >
              Graph
            </button>
            <button
              className={`tab ${activeTab === 'diff' ? 'active' : ''}`}
              onClick={() => setActiveTab('diff')}
            >
              Diff
            </button>
          </div>

          <div className="export-buttons">
            <button onClick={() => handleExport('json')} className="btn-secondary">Export JSON</button>
            <button onClick={() => handleExport('html')} className="btn-secondary">Export HTML</button>
            <button onClick={() => handleExport('pdf')} className="btn-secondary" disabled>Export PDF (Coming Soon)</button>
          </div>

          <div className="tab-content">
            {activeTab === 'overview' && (
              <div className="overview-tab">
                <h4>Analysis Overview</h4>
                <pre>{JSON.stringify(results, null, 2)}</pre>
              </div>
            )}

            {activeTab === 'functions' && (
              <div className="functions-tab">
                <h4>Functions</h4>

                {/* Search and Filter Controls */}
                <div className="search-filter-controls">
                  <div className="search-box">
                    <input
                      type="text"
                      placeholder="Search functions..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="search-input"
                    />
                  </div>

                  <div className="filter-select">
                    <select
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                      className="filter-dropdown"
                    >
                      <option value="all">All Functions</option>
                      <option value="high_complexity">High Complexity (>10)</option>
                      <option value="large_functions">Large Functions (>100 bytes)</option>
                      <option value="entry_points">Entry Points</option>
                    </select>
                  </div>
                </div>

                {results.functions ? (
                  <div className="functions-list">
                    {getFilteredFunctions().map((func: any, index: number) => (
                      <div key={index} className="function-item">
                        <h5>{func.name || `Function ${index}`}</h5>
                        <p>Address: {func.address}</p>
                        <p>Size: {func.size} bytes</p>
                        <p>Complexity: {func.complexity}</p>
                        {func.is_entry_point && <span className="entry-point-badge">Entry Point</span>}
                      </div>
                    ))}
                    {getFilteredFunctions().length === 0 && (
                      <p className="no-results">No functions match the current search and filter criteria.</p>
                    )}
                  </div>
                ) : (
                  <p>No function data available</p>
                )}
              </div>
            )}

            {activeTab === 'graph' && (
              <div className="graph-tab">
                <h4>Function Call Graph</h4>
                {results.functions ? (
                  <FunctionGraph
                    functions={results.functions.map((func: any, index: number) => ({
                      id: func.address || `func_${index}`,
                      name: func.name || `Function ${index}`,
                      address: func.address || '0x0',
                      size: func.size || 0,
                      complexity: func.complexity || 0
                    }))}
                    edges={[]} // TODO: Add actual edges from analysis
                    onNodeClick={(node) => console.log('Node clicked:', node)}
                  />
                ) : (
                  <p>No function data available for graph</p>
                )}
              </div>
            )}

            {activeTab === 'diff' && (
              <div className="diff-tab">
                <h4>Binary Diff Viewer</h4>
                <p className="diff-note">
                  Compare this binary with another version or different binary.
                  Upload or select a second binary to see differences.
                </p>
                {/* TODO: Add file upload for second binary */}
                <div className="diff-placeholder">
                  <BinaryDiffViewer
                    binary1={binary}
                    binary2="second_binary.exe"
                    diffs={[
                      {
                        address: "0x00401000",
                        type: "modified",
                        oldValue: "push ebp",
                        newValue: "push ebx",
                        description: "Function prologue modified"
                      },
                      {
                        address: "0x00401050",
                        type: "added",
                        newValue: "call 0x00402000",
                        description: "New function call added"
                      },
                      {
                        address: "0x00401500",
                        type: "removed",
                        oldValue: "xor eax, eax",
                        description: "Dead code removed"
                      }
                    ]}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default AnalysisPanel

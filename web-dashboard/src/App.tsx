import { useState } from 'react'
import './App.css'
import BinaryExplorer from './components/BinaryExplorer'
import AnalysisPanel from './components/AnalysisPanel'
import ChatInterface from './components/ChatInterface'

function App() {
  const [selectedBinary, setSelectedBinary] = useState<string | null>(null)
  const [analysisResults, setAnalysisResults] = useState<any>(null)

  return (
    <div className="app">
      <header className="app-header">
        <h1>GhidraInsight</h1>
        <p>AI-Assisted Reverse Engineering Platform</p>
      </header>

      <div className="app-container">
        <aside className="sidebar">
          <BinaryExplorer
            onSelectBinary={setSelectedBinary}
            selectedBinary={selectedBinary}
          />
        </aside>

        <main className="main-content">
          {selectedBinary ? (
            <div className="content-grid">
              <section className="analysis-section">
                <AnalysisPanel
                  binary={selectedBinary}
                  onResults={setAnalysisResults}
                />
              </section>

              <section className="chat-section">
                <ChatInterface
                  binary={selectedBinary}
                  analysis={analysisResults}
                />
              </section>
            </div>
          ) : (
            <div className="welcome">
              <h2>Welcome to GhidraInsight</h2>
              <p>Select or upload a binary to begin analysis</p>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

export default App

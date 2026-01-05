import React, { useState } from 'react'

interface BinaryDiff {
  address: string
  type: 'added' | 'removed' | 'modified'
  oldValue?: string
  newValue?: string
  description: string
}

interface BinaryDiffViewerProps {
  binary1: string
  binary2: string
  diffs: BinaryDiff[]
}

const BinaryDiffViewer: React.FC<BinaryDiffViewerProps> = ({
  binary1,
  binary2,
  diffs
}) => {
  const [selectedDiff, setSelectedDiff] = useState<BinaryDiff | null>(null)
  const [filterType, setFilterType] = useState<'all' | 'added' | 'removed' | 'modified'>('all')

  const filteredDiffs = diffs.filter(diff =>
    filterType === 'all' || diff.type === filterType
  )

  const getDiffStats = () => {
    const stats = {
      added: diffs.filter(d => d.type === 'added').length,
      removed: diffs.filter(d => d.type === 'removed').length,
      modified: diffs.filter(d => d.type === 'modified').length
    }
    return stats
  }

  const stats = getDiffStats()

  return (
    <div className="binary-diff-viewer">
      <div className="diff-header">
        <h4>Binary Diff: {binary1} vs {binary2}</h4>
        <div className="diff-stats">
          <span className="stat added">+{stats.added} added</span>
          <span className="stat removed">-{stats.removed} removed</span>
          <span className="stat modified">~{stats.modified} modified</span>
        </div>
      </div>

      <div className="diff-controls">
        <div className="filter-buttons">
          <button
            className={`filter-btn ${filterType === 'all' ? 'active' : ''}`}
            onClick={() => setFilterType('all')}
          >
            All ({diffs.length})
          </button>
          <button
            className={`filter-btn added ${filterType === 'added' ? 'active' : ''}`}
            onClick={() => setFilterType('added')}
          >
            Added ({stats.added})
          </button>
          <button
            className={`filter-btn removed ${filterType === 'removed' ? 'active' : ''}`}
            onClick={() => setFilterType('removed')}
          >
            Removed ({stats.removed})
          </button>
          <button
            className={`filter-btn modified ${filterType === 'modified' ? 'active' : ''}`}
            onClick={() => setFilterType('modified')}
          >
            Modified ({stats.modified})
          </button>
        </div>
      </div>

      <div className="diff-content">
        <div className="diff-list">
          {filteredDiffs.map((diff, index) => (
            <div
              key={index}
              className={`diff-item ${diff.type} ${selectedDiff === diff ? 'selected' : ''}`}
              onClick={() => setSelectedDiff(diff)}
            >
              <div className="diff-indicator">
                {diff.type === 'added' && '+'}
                {diff.type === 'removed' && '-'}
                {diff.type === 'modified' && '~'}
              </div>
              <div className="diff-address">{diff.address}</div>
              <div className="diff-description">{diff.description}</div>
            </div>
          ))}
          {filteredDiffs.length === 0 && (
            <div className="no-diffs">
              No differences found with current filter.
            </div>
          )}
        </div>

        {selectedDiff && (
          <div className="diff-details">
            <h5>Difference Details</h5>
            <div className="detail-row">
              <strong>Address:</strong> {selectedDiff.address}
            </div>
            <div className="detail-row">
              <strong>Type:</strong>
              <span className={`type-badge ${selectedDiff.type}`}>
                {selectedDiff.type.toUpperCase()}
              </span>
            </div>
            <div className="detail-row">
              <strong>Description:</strong> {selectedDiff.description}
            </div>
            {selectedDiff.oldValue && (
              <div className="detail-row">
                <strong>Old Value:</strong>
                <code>{selectedDiff.oldValue}</code>
              </div>
            )}
            {selectedDiff.newValue && (
              <div className="detail-row">
                <strong>New Value:</strong>
                <code>{selectedDiff.newValue}</code>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default BinaryDiffViewer

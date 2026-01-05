import React, { useState } from 'react'

interface BinaryExplorerProps {
  onSelectBinary: (binary: string) => void
  selectedBinary: string | null
}

const BinaryExplorer: React.FC<BinaryExplorerProps> = ({
  onSelectBinary,
  selectedBinary,
}) => {
  const [isDragging, setIsDragging] = useState(false)

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)

    const files = e.dataTransfer.files
    if (files.length > 0) {
      const file = files[0]
      onSelectBinary(file.name)
    }
  }

  return (
    <div className="binary-explorer">
      <h3>Binary Explorer</h3>

      <div
        className={`drop-zone ${isDragging ? 'dragging' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <p>Drag and drop a binary file here</p>
        <p className="text-sm">or use the file picker</p>
      </div>

      {selectedBinary && (
        <div className="selected-binary">
          <h4>Selected: {selectedBinary}</h4>
          <div className="binary-info">
            {/* Binary info will be populated here */}
          </div>
        </div>
      )}
    </div>
  )
}

export default BinaryExplorer

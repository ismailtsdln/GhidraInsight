import React, { useState } from 'react'

interface ChatInterfaceProps {
  binary: string
  analysis: any
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({ binary, analysis }) => {
  const [messages, setMessages] = useState<Array<{ role: string; content: string }>>([])
  const [input, setInput] = useState('')

  const handleSendMessage = async () => {
    if (!input.trim()) return

    const userMessage = { role: 'user', content: input }
    setMessages([...messages, userMessage])
    setInput('')

    try {
      // TODO: Call AI endpoint
      const response = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: input,
          binary,
          analysis,
        }),
      })
      const data = await response.json()
      setMessages((prev) => [...prev, { role: 'assistant', content: data.response }])
    } catch (error) {
      console.error('Query failed:', error)
    }
  }

  return (
    <div className="chat-interface">
      <h3>AI Analysis Chat</h3>

      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            <p>{msg.content}</p>
          </div>
        ))}
      </div>

      <div className="input-group">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
          placeholder="Ask about the binary..."
        />
        <button onClick={handleSendMessage} className="btn-primary">
          Send
        </button>
      </div>
    </div>
  )
}

export default ChatInterface

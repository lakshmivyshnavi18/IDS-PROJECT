import { useState, useRef, useEffect } from 'react';
import { v4 as uuidv4 } from 'uuid';
import ReactMarkdown from 'react-markdown';
import { Link } from 'react-router-dom';
import '../index.css';
import '../toggle.css';

function ChatApp() {
  const [messages, setMessages] = useState([
    { id: '1', role: 'llm', content: 'Hello! I am a secure AI assistant. How can I help you today?' }
  ]);
  const [input, setInput] = useState('');
  const [sessionId] = useState(uuidv4());
  const [isProtected, setIsProtected] = useState(true);
  
  const chatEndRef = useRef(null);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);


  const handleSend = async () => {
    if (!input.trim()) return;
    
    const userMsg = { id: uuidv4(), role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput('');

    try {
      const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          session_id: sessionId,
          user_id: 'demo-user',
          prompt: userMsg.content,
          is_protected: isProtected
        })
      });
      const data = await response.json();
      
      setMessages(prev => [...prev, {
        id: uuidv4(),
        role: 'llm',
        content: data.response
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        id: uuidv4(),
        role: 'llm',
        content: 'Error: Make sure the FastAPI backend is running on port 8000.'
      }]);
    }

    // Removed simulated Admin Dashboard alerts - now fetched via polling API
  };

  return (
    <div className="app-container">
      {/* Sidebar / Admin Dashboard Lite */}
      <aside className="dashboard-sidebar">
        <button className="new-chat-btn" onClick={() => window.location.reload()}>
          <svg stroke="currentColor" fill="none" strokeWidth="2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round" height="16" width="16" xmlns="http://www.w3.org/2000/svg">
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <line x1="5" y1="12" x2="19" y2="12"></line>
          </svg>
          New Chat
        </button>

        <div style={{ marginBottom: '24px', padding: '12px', background: isProtected ? 'rgba(16,163,127,0.1)' : 'rgba(239,68,68,0.1)', borderRadius: '8px', border: isProtected ? '1px solid rgba(16,163,127,0.3)' : '1px solid rgba(239,68,68,0.3)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: '600', color: isProtected ? '#10a37f' : '#ef4444' }}>
              {isProtected ? '🛡️ IDS: Protected' : '⚠️ IDS: Off'}
            </span>
            <label className="switch">
              <input type="checkbox" checked={isProtected} onChange={(e) => setIsProtected(e.target.checked)} />
              <span className="slider round"></span>
            </label>
          </div>
          <p style={{ fontSize: '11px', color: '#9b9b9b' }}>
            {isProtected ? 'CNN-LSTM monitoring active. Threats logged to Admin Dashboard.' : 'Unprotected Mode. No monitoring. LLM has no restrictions.'}
          </p>
        </div>

        <Link to="/admin" style={{ textDecoration: 'none' }}>
          <div className="new-chat-btn" style={{ justifyContent: 'center', background: 'rgba(16, 163, 127, 0.1)', color: '#10a37f', borderColor: '#10a37f' }}>
            Open Admin Dashboard
          </div>
        </Link>
        
        <div className="chat-history-sidebar">
          <div className="history-group">
            <h3>Today</h3>
            <div className="history-item active">Intrusion Detection Test</div>
            <div className="history-item">System Architecture...</div>
          </div>
          <div className="history-group">
            <h3>Previous 7 Days</h3>
            <div className="history-item">Reverse Shell Exploit...</div>
            <div className="history-item">What is Kali Linux?</div>
            <div className="history-item">Python Subprocess Hook...</div>
          </div>
        </div>
      </aside>

      {/* Main Chat Interface */}
      <main className="chat-main">
        {/* Mode Banner */}
        <div style={{
          padding: '10px 24px',
          background: isProtected ? 'rgba(16,163,127,0.08)' : 'rgba(239,68,68,0.08)',
          borderBottom: isProtected ? '1px solid rgba(16,163,127,0.2)' : '1px solid rgba(239,68,68,0.2)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '13px',
          color: isProtected ? '#10a37f' : '#ef4444'
        }}>
          {isProtected
            ? '🛡️ Protected Mode — CNN-LSTM IDS is actively monitoring this conversation'
            : '⚠️ Unprotected Mode — No IDS monitoring. AI has no restrictions.'}
        </div>

        <div className="chat-history">
          {messages.map((msg) => (
            <div key={msg.id} className={`message-wrapper ${msg.role}`}>
              <div className="message-container">
                <div className={`avatar ${msg.role}`}>
                  {msg.role === 'user' ? 'U' : 'AI'}
                </div>
                <div className="message-content">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
            </div>
          ))}
          <div ref={chatEndRef} />
        </div>
        
        <div className="input-container">
          <div className="input-box">
            <input 
              type="text" 
              placeholder="Message secure LLM..." 
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            />
            <button onClick={handleSend}>
              <svg stroke="currentColor" fill="none" strokeWidth="2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round" height="16" width="16" xmlns="http://www.w3.org/2000/svg">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </div>
          <div className="disclaimer">
            AI can make mistakes. This session is actively monitored by the CNN-LSTM Intrusion Detection System.
          </div>
        </div>
      </main>
    </div>
  );
}

export default ChatApp;

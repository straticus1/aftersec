"use client";

import React, { useState, useRef, useEffect } from 'react';
import { Bot, User, Send, ChevronRight, Zap, Terminal, ShieldAlert, Cpu } from 'lucide-react';
import { useTenant } from '@/lib/contexts/TenantContext';

type Message = {
  id: string;
  role: 'user' | 'bandit';
  content: string;
  isStreamed?: boolean;
};

export default function BanditAIPage() {
  const { currentTenant } = useTenant();
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'msg-0',
      role: 'bandit',
      content: `Greetings. I'm **Bandit AI**, your on-system security expert for \`${currentTenant?.name || 'Local System'}\`. 
      
I have deep hooks into the XNU Kernel, Unified Logs, and Endpoint AI neural baselines. Ask me about your real-time security posture, memory forensics, or to translate raw telemetry into plain English.`,
    }
  ]);
  const [isProcessing, setIsProcessing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!input.trim() || isProcessing) return;

    const userQuery = input.trim();
    const newUserMsg: Message = { id: `msg-${Date.now()}`, role: 'user', content: userQuery };
    
    setMessages(prev => [...prev, newUserMsg]);
    setInput('');
    setIsProcessing(true);

    // Mock natural language "Bandit AI" response stream
    setTimeout(() => {
      let replyText = '';
      const lcase = userQuery.toLowerCase();
      
      if (lcase.includes('memory') || lcase.includes('xray') || lcase.includes('x-ray')) {
        replyText = "I've analyzed the current `Process X-Ray` regions. I noticed `Electron` allocating a highly suspicious `rwx` (Read-Write-Execute) mapped memory region at `0x1405a0000`. This violates standard codesign parameters and is highly indicative of runtime memory injection. I recommend we immediately isolate the PID and sever its active network sockets.";
      } else if (lcase.includes('firewall') || lcase.includes('block') || lcase.includes('network')) {
        replyText = "Looking at the `PF` (Packet Filter) kernel tables... The firewall blocked `10.0.0.5` because it triggered a known Typosquatting C2 beacon heuristic over UDP port 53 (DNS). The domain queried was `apple-update-metrics.xyz`. We've enforced a permanent null-route for that ASN locally via our Netfilter module.";
      } else if (lcase.includes('endpoint ai') || lcase.includes('baseline') || lcase.includes('drift')) {
        replyText = "Our local Endpoint AI neural baseline currently shows an anomaly drift of `0.02%` across 5 endpoints. The `fin-macbook-pro` is successfully in **Enforcement Mode**. Everything is looking rock solid—there are no significant deviations from expected behavioral trees recorded in the last 24 hours.";
      } else {
        replyText = "I'm reviewing the telemetry context across our rules engine. No critical indicators of compromise match that specific query, but I'm monitoring the Unified Logs in real-time. Do you want me to write a custom Starlark Detection Rule for that specific behavior so we can track it globally?";
      }

      setMessages(prev => [...prev, { id: `msg-${Date.now() + 1}`, role: 'bandit', content: replyText, isStreamed: true }]);
      setIsProcessing(false);
    }, 1500);
  };

  const handleSuggestionClick = (text: string) => {
    setInput(text);
  };

  return (
    <div className="h-screen flex flex-col pt-4 px-6 pb-6 relative overflow-hidden">
      {/* Background Decorators */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-900/10 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="absolute bottom-[-100px] left-[-100px] w-[600px] h-[600px] bg-blue-900/10 rounded-full blur-3xl pointer-events-none -z-10" />

      <header className="flex-shrink-0 flex items-center gap-3 mb-6 pb-4 border-b border-gray-800">
        <div className="h-10 w-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-500/20">
          <Bot className="h-6 w-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            Bandit AI 
            <span className="bg-indigo-500/10 text-indigo-400 text-[10px] uppercase font-black px-2 py-0.5 rounded-full border border-indigo-500/20">On-System Expert</span>
          </h1>
          <p className="text-sm text-gray-400 font-medium">NLP Analysis & Natural Language Telemetry Queries</p>
          <p className="text-xs text-indigo-400/80 font-bold italic mt-0.5">&quot;We keep bandits out. You keep your data in.&quot;</p>
        </div>
      </header>

      {/* Main Chat Area */}
      <div className="flex-1 overflow-y-auto pr-2 pb-6 space-y-6 flex flex-col" id="chat-container">
        {messages.map((msg) => (
          <div key={msg.id} className={`flex w-full gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            {msg.role === 'bandit' && (
              <div className="flex-shrink-0 h-8 w-8 rounded bg-gray-800 border border-gray-700 flex items-center justify-center mt-1">
                <Bot className="h-5 w-5 text-indigo-400" />
              </div>
            )}
            
            <div className={`max-w-[75%] rounded-2xl px-5 py-3.5 shadow-sm text-[15px] leading-relaxed ${
              msg.role === 'user' 
                ? 'bg-gradient-to-b from-indigo-600 to-indigo-700 text-white rounded-tr-sm border border-indigo-500' 
                : 'bg-gray-800/80 text-gray-200 rounded-tl-sm border border-gray-700'
            }`}>
              {/* Basic mock parsing of bold and code blocks */}
              {msg.content.split('`').map((part, i) => 
                i % 2 === 1 
                  ? <code key={i} className="bg-black/30 font-mono text-[13px] px-1.5 py-0.5 rounded text-indigo-200">{part}</code>
                  : <span key={i} dangerouslySetInnerHTML={{ __html: part.replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>') }} />
              )}
            </div>

            {msg.role === 'user' && (
              <div className="flex-shrink-0 h-8 w-8 rounded-full bg-gray-700 flex items-center justify-center mt-1">
                <User className="h-5 w-5 text-gray-300" />
              </div>
            )}
          </div>
        ))}
        
        {isProcessing && (
          <div className="flex w-full gap-4 justify-start">
            <div className="flex-shrink-0 h-8 w-8 rounded bg-gray-800 border border-gray-700 flex items-center justify-center mt-1">
              <Bot className="h-5 w-5 text-indigo-400 animate-pulse" />
            </div>
            <div className="bg-gray-800/80 rounded-2xl rounded-tl-sm border border-gray-700 px-5 py-3.5 flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce" style={{ animationDelay: '0ms' }} />
              <div className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce" style={{ animationDelay: '150ms' }} />
              <div className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce" style={{ animationDelay: '300ms' }} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="flex-shrink-0 pt-4">
        {/* Suggested Prompts */}
        <div className="flex gap-2 mb-3 overflow-x-auto pb-1 no-scrollbar">
          <button 
            onClick={() => handleSuggestionClick("Analyze the current process X-Ray memory baseline.")}
            className="whitespace-nowrap flex items-center gap-2 bg-gray-800/60 hover:bg-gray-700 border border-gray-700 text-gray-300 text-xs px-3 py-1.5 rounded-full transition-colors"
          >
            <Cpu className="h-3 w-3 text-indigo-400" /> Analyze X-Ray Memory
          </button>
          <button 
            onClick={() => handleSuggestionClick("Why did the network firewall block 10.0.0.5?")}
            className="whitespace-nowrap flex items-center gap-2 bg-gray-800/60 hover:bg-gray-700 border border-gray-700 text-gray-300 text-xs px-3 py-1.5 rounded-full transition-colors"
          >
            <ShieldAlert className="h-3 w-3 text-red-400" /> Explain Firewall Drop
          </button>
          <button 
            onClick={() => handleSuggestionClick("What is the anomaly drift on our Endpoint AI baselines?")}
            className="whitespace-nowrap flex items-center gap-2 bg-gray-800/60 hover:bg-gray-700 border border-gray-700 text-gray-300 text-xs px-3 py-1.5 rounded-full transition-colors"
          >
            <Zap className="h-3 w-3 text-amber-400" /> Query Baseline Drift
          </button>
        </div>

        <form onSubmit={handleSend} className="relative flex items-center">
          <div className="absolute left-4 text-gray-500 flex items-center">
            <Terminal className="h-5 w-5" />
          </div>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isProcessing}
            placeholder="Ask Bandit AI about your endpoint telemetry or compliance posture..."
            className="w-full bg-gray-900 border border-gray-700 rounded-xl py-4 pl-12 pr-14 text-white placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={!input.trim() || isProcessing}
            className="absolute right-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 disabled:text-gray-500 text-white h-10 w-10 flex items-center justify-center rounded-lg transition-colors cursor-pointer"
          >
            <Send className="h-4 w-4 ml-0.5" />
          </button>
        </form>
        <div className="text-center mt-3 text-[11px] text-gray-500">
          Bandit AI evaluates sensitive telemetry locally using Endpoint LLMs.
        </div>
      </div>
    </div>
  );
}

"use client";

import React, { useState } from 'react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { Sparkles, AlertTriangle, ShieldCheck, TerminalSquare, Cpu, X, Check } from 'lucide-react';
import IntentGraph from '@/components/IntentGraph';

const mockAlerts = [
  { id: 'ALT-9921', severity: 'critical', title: 'Suspicious Child Process Inheritance', endpoint: 'mac-studio-dev', time: '2 mins ago' },
  { id: 'ALT-9920', severity: 'high', title: 'Unusual Network Beaconing to Russia', endpoint: 'prod-api-02', time: '15 mins ago' },
  { id: 'ALT-9919', severity: 'medium', title: 'Multiple Failed SSH Auth Attempts', endpoint: 'db-replica-01', time: '1 hour ago' },
];

export default function AITriagePage() {
  const { currentTenant } = useTenant();
  const [selectedAlert, setSelectedAlert] = useState(mockAlerts[0]);
  const [isTyping, setIsTyping] = useState(false);
  const [messages, setMessages] = useState([
    { role: 'assistant', text: "I've analyzed event ALT-9921. At 14:02 UTC, the `Terminal` application spawned `curl` which was immediately piped into `python3`. The Python process then attempted to read `~/Library/Keychains/login.keychain-db` and open a reverse shell on port 4444.\n\n**Confidence Analysis**:\n- False Positive Probability: < 1%\n- MITRE Tactic: Credential Access (T1555)\n\nI recommend immediate isolation of the endpoint." }
  ]);

  const handleAction = (actionLabel: string, replyMessage: string) => {
    setMessages(prev => [...prev, { role: 'user', text: actionLabel }]);
    setIsTyping(true);
    setTimeout(() => {
      setMessages(prev => [...prev, { role: 'assistant', text: replyMessage }]);
      setIsTyping(false);
    }, 1500);
  };

  return (
    <div className="flex h-screen w-full bg-gray-950 text-gray-200 overflow-hidden">
      {/* Left Sidebar: Alerts List */}
      <div className="w-80 border-r border-gray-800 bg-gray-900/50 flex flex-col shrink-0">
        <div className="p-4 border-b border-gray-800 bg-gray-900">
          <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-1">
            <Sparkles className="h-5 w-5 text-indigo-400" />
            Genkit Triage Swarm
          </h2>
          <p className="text-xs text-indigo-400 font-semibold uppercase tracking-wider">Tenant: {currentTenant?.name}</p>
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {mockAlerts.map(alert => (
            <button
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className={`w-full text-left p-4 rounded-xl transition-all border ${
                selectedAlert.id === alert.id ? 'bg-indigo-900/20 border-indigo-500/50 shadow-lg shadow-indigo-900/20' : 'bg-gray-900 shadow border-gray-800 hover:border-gray-700'
              }`}
            >
              <div className="flex justify-between items-start mb-2">
                <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                  alert.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  alert.severity === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                }`}>
                  {alert.severity}
                </span>
                <span className="text-xs text-gray-500 font-mono">{alert.time}</span>
              </div>
              <h3 className="text-sm font-semibold text-gray-200 mb-1">{alert.title}</h3>
              <p className="text-xs text-gray-500 font-mono">{alert.id} • {alert.endpoint}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Main Area: Swarm Chat */}
      <div className="flex-1 flex flex-col bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/10 via-gray-950 to-gray-950 relative">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 bg-gray-900/80 backdrop-blur shrink-0 flex justify-between items-center z-10">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              Triage Report: {selectedAlert.id}
            </h1>
            <p className="text-sm text-gray-400 mt-1 font-mono">{selectedAlert.title} on {selectedAlert.endpoint}</p>
          </div>
          <div className="flex gap-2">
            <span className="bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 px-3 py-1 flex items-center gap-2 rounded-lg text-xs font-bold uppercase tracking-wider">
               <Cpu className="h-4 w-4" /> Multi-LLM Consensus Reached
            </span>
          </div>
        </div>

        {/* Chat Log & Visualization */}
        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          <IntentGraph />
          
          {messages.map((msg, i) => (
            <div key={i} className={`flex max-w-3xl ${msg.role === 'user' ? 'ml-auto justify-end' : ''}`}>
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 rounded bg-indigo-900 border border-indigo-500/50 flex items-center justify-center mr-4 shrink-0 shadow-[0_0_15px_rgba(99,102,241,0.3)]">
                  <Sparkles className="h-5 w-5 text-indigo-300" />
                </div>
              )}
              <div className={`p-4 rounded-2xl ${msg.role === 'user' ? 'bg-gray-800 border-gray-700 text-gray-200 border' : 'bg-gray-900/80 border border-indigo-500/20 text-gray-300 shadow-xl'}`}>
                 <div className="text-sm leading-relaxed whitespace-pre-wrap">{msg.text}</div>
              </div>
            </div>
          ))}
          {isTyping && (
            <div className="flex max-w-3xl">
              <div className="w-8 h-8 rounded bg-indigo-900 border border-indigo-500/50 flex items-center justify-center mr-4 shrink-0 shadow-[0_0_15px_rgba(99,102,241,0.3)]">
                 <Sparkles className="h-5 w-5 text-indigo-300" />
              </div>
              <div className="p-4 rounded-xl bg-gray-900/80 border border-indigo-500/20 flex gap-1 items-center">
                 <div className="w-2 h-2 bg-indigo-400 rounded-full animate-bounce"></div>
                 <div className="w-2 h-2 bg-indigo-400 rounded-full animate-bounce delay-75"></div>
                 <div className="w-2 h-2 bg-indigo-400 rounded-full animate-bounce delay-150"></div>
              </div>
            </div>
          )}
        </div>

        {/* Action Panel */}
        <div className="p-4 bg-gray-900 border-t border-gray-800 shrink-0">
           <p className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3 px-2 flex items-center gap-2">
             <TerminalSquare className="h-4 w-4" /> Suggested Agent Commands
           </p>
           <div className="flex gap-3">
             <button 
               disabled={isTyping}
               onClick={() => handleAction('Isolate endpoint and run memory dump.', 'Understood. Dispatching `isolate_node` instruction to edge agent via gRPC. Memory dump initiated and will be available in `/xray` shortly. Target isolated successfully.')}
               className="bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors flex items-center gap-2"
             >
               <X className="h-4 w-4" /> Isolate & Dump Memory
             </button>
             <button 
               disabled={isTyping}
               onClick={() => handleAction('Generate a Starlark rule to detect this specific python behavior globally.', 'Generating Starlark rule... I have drafted `detect_python_keychain_dump.star`. You can review, test, and deploy this in the Detection Rules builder.')}
               className="bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-900/20 px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors flex items-center gap-2 disabled:opacity-50"
             >
               <Sparkles className="h-4 w-4" /> Generate Starlark Rule
             </button>
             <button 
               disabled={isTyping}
               onClick={() => handleAction('Mark as False Positive.', 'Alert marked as False Positive. I will adjust the confidence weights for similar future heuristic matches involving `curl` piped to `python3` on developer endpoints.')}
               className="bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors flex items-center gap-2 disabled:opacity-50"
             >
               <Check className="h-4 w-4" /> Mark False Positive
             </button>
           </div>
        </div>
      </div>
    </div>
  );
}

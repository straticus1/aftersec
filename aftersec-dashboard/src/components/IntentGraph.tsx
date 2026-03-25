import React from 'react';
import { Terminal, Code, Globe, ChevronRight, ShieldAlert } from 'lucide-react';

export default function IntentGraph() {
  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-6 mt-4 relative overflow-hidden">
      <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
        <ShieldAlert className="w-32 h-32" />
      </div>
      
      <h3 className="text-sm font-bold text-gray-300 mb-6 uppercase tracking-wider">Process Execution Chain</h3>
      
      <div className="flex flex-col md:flex-row items-center gap-4 relative z-10 w-full overflow-x-auto pb-4">
        
        {/* Node 1: Terminal */}
        <div className="flex flex-col items-center bg-gray-950 border border-gray-800 p-4 rounded-xl min-w-[200px] shadow-lg">
          <Terminal className="h-6 w-6 text-gray-400 mb-2" />
          <div className="font-mono text-sm text-gray-200">/Applications/Terminal.app</div>
          <div className="text-xs text-gray-500 mt-1">PID: 402</div>
          <div className="mt-3 text-[10px] bg-gray-800 px-2 py-1 rounded text-gray-400 font-semibold border border-gray-700">
            com.apple.security.get-task-allow
          </div>
        </div>

        <ChevronRight className="text-gray-600 hidden md:block shrink-0" />
        <div className="w-0.5 h-4 bg-gray-600 md:hidden shrink-0"></div>

        {/* Node 2: bash */}
        <div className="flex flex-col items-center bg-gray-950 border border-gray-800 p-4 rounded-xl min-w-[200px] shadow-lg">
          <Code className="h-6 w-6 text-indigo-400 mb-2" />
          <div className="font-mono text-sm text-gray-200">/bin/bash</div>
          <div className="text-xs text-gray-500 mt-1">PID: 8911</div>
          <div className="mt-3 text-[10px] bg-indigo-900/30 px-2 py-1 rounded text-indigo-300 font-semibold border border-indigo-500/30">
            inherited privileges
          </div>
        </div>

        <ChevronRight className="text-red-500 hidden md:block shrink-0" />
        <div className="w-0.5 h-4 bg-red-500 md:hidden shrink-0"></div>

        {/* Node 3: curl */}
        <div className="flex flex-col items-center bg-red-950/20 border border-red-900/50 p-4 rounded-xl min-w-[200px] shadow-[0_0_15px_rgba(153,27,27,0.2)]">
          <Globe className="h-6 w-6 text-red-500 mb-2" />
          <div className="font-mono text-sm text-red-400 font-bold">curl -sL [REDACTED]</div>
          <div className="text-xs text-red-500/70 mt-1 font-mono">PID: 8912</div>
          <div className="mt-3 text-[10px] bg-red-500/20 px-2 py-1 rounded text-red-300 font-semibold border border-red-500/30 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" /> network_outbound_anomaly
          </div>
        </div>

      </div>
    </div>
  );
}

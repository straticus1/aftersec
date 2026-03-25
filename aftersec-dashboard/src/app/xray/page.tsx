"use client";

import React, { useState } from 'react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { Cpu, MemoryStick, Search, AlertOctagon, Terminal, PlaySquare, XCircle, CodeXml } from 'lucide-react';

const mockProcesses = [
  { pid: 4892, name: 'curl', path: '/usr/bin/curl', user: 'ryan', state: 'running', threatScore: 85, flagged: true },
  { pid: 1023, name: 'sshd', path: '/usr/sbin/sshd', user: 'root', state: 'sleeping', threatScore: 10, flagged: false },
  { pid: 88, name: 'launchd', path: '/sbin/launchd', user: 'root', state: 'running', threatScore: 5, flagged: false },
  { pid: 5012, name: 'python3', path: '/opt/homebrew/bin/python3', user: 'ryan', state: 'running', threatScore: 40, flagged: false },
  { pid: 5199, name: 'bash', path: '/bin/bash', user: 'ryan', state: 'running', threatScore: 60, flagged: true },
];

const mockMemoryRegions = [
  { address: '0x00007ff80000', size: '16MB', perms: 'r-x', desc: 'libSystem.B.dylib (Core Library)', type: 'dylib' },
  { address: '0x0000000104a0', size: '4KB', perms: 'rwx', desc: 'JIT Compiled Payload / Obfuscated Shellcode', type: 'shellcode', alert: true },
  { address: '0x0000000108f0', size: '8KB', perms: 'rw-', desc: 'Heap Allocation (Identified: AWS_ACCESS_KEY_ID)', type: 'secret', alert: true },
  { address: '0x00007ff81230', size: '2MB', perms: 'r-x', desc: 'libcrypto.dylib', type: 'dylib' },
  { address: '0x000002000000', size: '1MB', perms: 'rw-', desc: 'Stack Frame', type: 'stack' },
];

export default function ProcessXRayPage() {
  const { currentTenant } = useTenant();
  const [selectedPid, setSelectedPid] = useState<number | null>(4892);
  
  const selectedProcess = mockProcesses.find(p => p.pid === selectedPid);

  return (
    <div className="flex h-screen w-full bg-gray-950 text-gray-200 overflow-hidden">
      {/* Left Sidebar: Process List */}
      <div className="w-80 border-r border-gray-800 bg-gray-900/50 flex flex-col">
        <div className="p-4 border-b border-gray-800 bg-gray-900">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Cpu className="h-5 w-5 text-indigo-400" />
            Live Endpoint Tasks
          </h2>
          <p className="text-xs text-gray-400 mt-1">Target: macbook-pro-ryan (Node 4)</p>
          <div className="mt-4 relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
            <input 
              type="text" 
              placeholder="Search running tasks..." 
              className="w-full bg-gray-950 border border-gray-800 rounded-md py-2 pl-9 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 text-gray-300"
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {mockProcesses.map((proc) => (
            <button
              key={proc.pid}
              onClick={() => setSelectedPid(proc.pid)}
              className={`w-full text-left p-3 rounded-lg transition-colors flex items-center justify-between ${
                selectedPid === proc.pid ? 'bg-indigo-600/20 border-indigo-500/50 border' : 'hover:bg-gray-800 border border-transparent'
              }`}
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className={`font-mono font-semibold ${proc.flagged ? 'text-red-400' : 'text-gray-300'}`}>{proc.name}</span>
                  {proc.flagged && <AlertOctagon className="h-3.5 w-3.5 text-red-500" />}
                </div>
                <div className="text-xs text-gray-500 font-mono mt-1">PID: {proc.pid} | User: {proc.user}</div>
              </div>
              <div className="text-right">
                <div className={`text-xs font-bold ${proc.threatScore > 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {proc.threatScore} / 100
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Area: Memory X-Ray */}
      <div className="flex-1 flex flex-col">
        {selectedProcess ? (
          <>
            {/* Header */}
            <div className="p-6 border-b border-gray-800 bg-gray-900 shrink-0">
              <div className="flex justify-between items-start">
                <div>
                  <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                    <Terminal className="h-6 w-6 text-gray-400" />
                    {selectedProcess.path}
                  </h1>
                  <div className="flex items-center gap-4 mt-2 text-sm">
                    <span className="bg-gray-800 px-2 py-1 rounded text-gray-300 font-mono">PID: {selectedProcess.pid}</span>
                    <span className={`px-2 py-1 rounded font-bold uppercase tracking-wider text-xs ${
                      selectedProcess.state === 'running' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-gray-800 text-gray-400'
                    }`}>
                      {selectedProcess.state}
                    </span>
                    {selectedProcess.flagged && (
                      <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-1 rounded font-bold uppercase tracking-wider text-xs flex items-center gap-1">
                        <AlertOctagon className="h-3 w-3" /> Malicious Behavior Detected
                      </span>
                    )}
                  </div>
                </div>
                <button className="bg-red-600 hover:bg-red-500 transition-colors text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 shadow-lg shadow-red-900/20">
                  <XCircle className="h-4 w-4" /> Kill Process
                </button>
              </div>
            </div>

            {/* Memory Visualization */}
            <div className="flex-1 overflow-y-auto p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/10 via-gray-950 to-gray-950">
              <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <MemoryStick className="h-5 w-5 text-indigo-400" />
                Live Memory Regions (VMA)
              </h3>
              
              <div className="space-y-3">
                {mockMemoryRegions.map((region, i) => (
                  <div key={i} className={`p-4 rounded-xl border ${region.alert ? 'bg-red-950/20 border-red-900/50 shadow-[0_0_15px_rgba(153,27,27,0.1)]' : 'bg-gray-900/50 border-gray-800'}`}>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-sm text-indigo-300 bg-indigo-900/30 px-2 py-1 rounded border border-indigo-500/20">
                          {region.address}
                        </span>
                        <span className={`text-sm font-semibold ${region.alert ? 'text-red-400' : 'text-gray-300'}`}>
                          {region.desc}
                        </span>
                      </div>
                      <div className="flex gap-4 text-xs font-mono text-gray-500">
                        <span>Perms: <span className={region.perms.includes('x') ? 'text-amber-400' : 'text-gray-400'}>{region.perms}</span></span>
                        <span>Size: {region.size}</span>
                      </div>
                    </div>
                    
                    {region.alert && region.type === 'secret' && (
                      <div className="mt-4 p-3 bg-gray-950 rounded-lg border border-red-900/30 font-mono text-xs overflow-x-auto text-red-300">
                        <div className="text-red-500 font-bold mb-1">// Extracted AWS Credentials via Memory Scan</div>
                        <div>00000000  41 4b 49 41 49 4f 53 46 4f 44 4e 4e 37 45 58 41  |AKIAIOSFODNN7EXA|</div>
                        <div>00000010  4d 50 4c 45 00 00 00 00 00 00 00 00 00 00 00 00  |MPLE............|</div>
                      </div>
                    )}
                    
                    {region.alert && region.type === 'shellcode' && (
                      <div className="mt-4 p-3 bg-gray-950 rounded-lg border border-red-900/30 font-mono text-xs overflow-x-auto text-amber-300">
                        <div className="text-red-500 font-bold mb-1">// Identified rwx execution region (JIT Shellcode)</div>
                        <div>00000000  48 31 c0 50 48 bf 2f 2f 62 69 6e 2f 73 68 57 48  |H1.PH.//bin/shWH|</div>
                        <div>00000010  89 e7 50 48 89 e2 57 48 89 e6 b0 3b 0f 05        |..PH..WH...;..|</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-gray-500">
            <CodeXml className="h-16 w-16 mb-4 text-gray-800" />
            <p className="text-lg font-medium text-gray-400">Select a process to view its memory space.</p>
          </div>
        )}
      </div>
    </div>
  );
}

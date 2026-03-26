"use client";

import React, { useState } from 'react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { ShieldCheck, ShieldAlert, FileWarning, KeyRound, CheckCircle2, Search, X } from 'lucide-react';

const mockBinaries = [
  { id: 'b1', name: 'Slack.app', path: '/Applications/Slack.app', signer: 'Developer ID Application: Slack Technologies, Inc.', status: 'valid', type: 'Apple Signed' },
  { id: 'b2', name: 'Docker.app', path: '/Applications/Docker.app', signer: 'Developer ID Application: Docker Inc', status: 'valid', type: 'Developer ID' },
  { id: 'b3', name: 'custom-internal-tool', path: '/usr/local/bin/custom-internal-tool', signer: 'None', status: 'unsigned', type: 'Ad-Hoc / Unsigned' },
  { id: 'b4', name: 'UnknownPayload', path: '/tmp/UnknownPayload', signer: 'Invalid Signature (Revoked)', status: 'invalid', type: 'Revoked' },
  { id: 'b5', name: 'CompanyVPN.app', path: '/Applications/CompanyVPN.app', signer: 'Developer ID Application: OldCompany', status: 'warning', type: 'Expiring Soon' },
];

export default function SignaturesPage() {
  const { currentTenant } = useTenant();
  const [selectedApp, setSelectedApp] = useState<{name: string, path: string} | null>(null);
  const [isResigning, setIsResigning] = useState(false);
  const [resignSuccess, setResignSuccess] = useState(false);

  const handleResign = () => {
    setIsResigning(true);
    setTimeout(() => {
      setIsResigning(false);
      setResignSuccess(true);
      setTimeout(() => {
        setResignSuccess(false);
        setSelectedApp(null);
      }, 2000);
    }, 1500);
  };

  return (
    <div className="min-h-screen relative p-8">
      <header className="mb-10 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white mb-2 flex items-center gap-3">
            <ShieldCheck className="h-8 w-8 text-indigo-400" />
            Code Signing & Trust
          </h1>
          <p className="text-gray-400 text-sm font-medium">
            Monitor macOS binary signatures and force-resign untrusted applications.
          </p>
        </div>
        <div className="relative w-64">
           <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
           <input 
             type="text" 
             placeholder="Search binaries..." 
             className="w-full bg-gray-900 border border-gray-800 rounded-lg py-2 pl-9 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 text-gray-300"
           />
        </div>
      </header>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-gray-800/50 text-xs uppercase font-medium text-gray-500">
              <tr>
                <th className="px-6 py-4">Binary Context</th>
                <th className="px-6 py-4">Signing Identity</th>
                <th className="px-6 py-4">Trust Status</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {mockBinaries.map((bin) => (
                <tr key={bin.id} className="hover:bg-gray-800/80 transition-colors group">
                  <td className="px-6 py-4">
                    <div className="font-bold text-gray-200">{bin.name}</div>
                    <div className="font-mono text-xs text-gray-500 mt-1">{bin.path}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className={`font-mono text-xs ${bin.status === 'valid' ? 'text-indigo-400' : 'text-gray-400'}`}>
                      {bin.signer}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 w-max ${
                      bin.status === 'valid' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 
                      bin.status === 'invalid' ? 'bg-red-500/10 text-red-400 border border-red-500/20 shadow-[0_0_10px_rgba(248,113,113,0.1)]' : 
                      bin.status === 'unsigned' ? 'bg-gray-800 text-gray-400 border border-gray-700' :
                      'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>
                      {bin.status === 'valid' && <ShieldCheck className="w-4 h-4" />}
                      {bin.status === 'invalid' && <ShieldAlert className="w-4 h-4" />}
                      {bin.status === 'warning' && <FileWarning className="w-4 h-4" />}
                      {bin.status === 'unsigned' && <div className="w-1.5 h-1.5 rounded-full bg-gray-500" />}
                      {bin.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right flex justify-end items-center gap-3">
                    <button className="text-gray-500 hover:text-white transition-colors font-semibold text-sm">
                      Analyze
                    </button>
                    {(bin.status === 'unsigned' || bin.status === 'invalid' || bin.status === 'warning') && (
                      <button 
                        onClick={() => setSelectedApp(bin)}
                        className="bg-indigo-600/20 text-indigo-400 hover:bg-indigo-600 hover:text-white border border-indigo-500/30 transition-colors font-bold text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 shadow-sm"
                      >
                        <KeyRound className="h-3.5 w-3.5" /> Force Resign
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Resign Modal */}
      {selectedApp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-lg shadow-2xl shadow-indigo-900/10 overflow-hidden flex flex-col">
            <div className="p-5 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <KeyRound className="h-5 w-5 text-indigo-400" />
                Enterprise Code Resigning
              </h2>
              <button disabled={isResigning} onClick={() => setSelectedApp(null)} className="text-gray-500 hover:text-white transition-colors">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 bg-gray-950 flex-1">
              {resignSuccess ? (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <CheckCircle2 className="h-16 w-16 text-emerald-500 mb-4 shadow-[0_0_20px_rgba(16,185,129,0.2)] rounded-full" />
                  <h3 className="text-xl font-bold text-white">Injection Successful</h3>
                  <p className="text-gray-400 mt-2 text-sm">Target <code className="text-indigo-400 font-mono">{selectedApp.name}</code> has been re-signed with Enterprise Certificate.</p>
                </div>
              ) : (
                <>
                  <p className="text-sm text-gray-300 mb-6 leading-relaxed">
                    You are explicitly trusting <span className="font-mono text-indigo-300 bg-indigo-900/30 px-1 rounded">{selectedApp.name}</span>. 
                    This will inject your global organization provisioning profile and code-signing certificate into the target binary.
                  </p>
                  
                  <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
                     <p className="text-xs font-bold text-gray-500 uppercase mb-2">Target Path</p>
                     <p className="text-sm font-mono text-gray-300 break-all">{selectedApp.path}</p>
                     
                     <p className="text-xs font-bold text-gray-500 uppercase mb-2 mt-4">Selected Keys</p>
                     <select className="w-full bg-gray-950 border border-gray-700 rounded p-2 text-sm text-gray-200 mt-1 focus:ring-1 focus:ring-indigo-500 outline-none">
                       <option>Enterprise Root CA: {currentTenant?.name}</option>
                       <option>Internal DevOps Signing Cert 2026</option>
                     </select>
                  </div>

                  <div className="flex justify-end gap-3">
                    <button 
                      onClick={() => setSelectedApp(null)}
                      disabled={isResigning}
                      className="px-4 py-2 text-sm font-semibold text-gray-400 hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                    <button 
                      onClick={handleResign}
                      disabled={isResigning}
                      className={`px-5 py-2 text-sm font-bold rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-indigo-900/20 ${
                        isResigning ? 'bg-indigo-600/50 text-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-500 text-white'
                      }`}
                    >
                      {isResigning ? (
                        <>Injecting Certificate...</>
                      ) : (
                        <><KeyRound className="w-4 h-4" /> Resign Application</>
                      )}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

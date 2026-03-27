import React from 'react';
import { getScans } from '@/lib/api';
import Link from 'next/link';

export default async function ScansPage() {
  const scans = await getScans();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-purple-500/30 overflow-hidden relative">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-fuchsia-900/20 via-slate-950 to-slate-950 h-[800px] -z-10 pointer-events-none"></div>
      
      <main className="max-w-7xl mx-auto px-8 py-12 relative z-10">
        <header className="flex justify-between items-center mb-12 border-b border-fuchsia-900/30 pb-6">
          <div className="flex flex-col">
            <div className="flex items-center gap-3 text-sm font-medium text-slate-400 mb-2 hover:text-fuchsia-400 transition-colors">
              <Link href="/">← Back to Dashboard</Link>
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-fuchsia-400 to-purple-600 drop-shadow-sm pb-1">
              Security Scans
            </h1>
          </div>
          <button className="px-5 py-2.5 rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 text-white transition-all font-medium shadow-[0_0_20px_rgba(192,38,211,0.3)] text-sm flex items-center gap-2">
            Initiate Scan
          </button>
        </header>

        <section className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-400">
              <thead className="bg-slate-900/80 text-xs uppercase font-medium text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4">Scan ID</th>
                  <th className="px-6 py-4">Hardware ID</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Date</th>
                  <th className="px-6 py-4">Findings</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-4 font-mono text-slate-200">{scan.id}</td>
                    <td className="px-6 py-4 font-mono text-fuchsia-300">{scan.endpointId}</td>
                    <td className="px-6 py-4">
                      <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-md text-xs font-semibold">
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-slate-400">
                      {new Date(scan.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      {scan.findingsCount > 0 ? (
                        <span className="text-red-400 font-bold">{scan.findingsCount} Issues</span>
                      ) : (
                        <span className="text-emerald-400">Clean</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <Link href={`/scans/${scan.id}`} className="text-slate-500 hover:text-fuchsia-400 transition-colors font-medium">View Details</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

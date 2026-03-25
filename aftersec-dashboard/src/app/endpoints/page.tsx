import React from 'react';
import { getEndpoints } from '@/lib/api';
import Link from 'next/link';

export default async function EndpointsPage() {
  const endpoints = await getEndpoints();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30 overflow-hidden relative">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/20 via-slate-950 to-slate-950 h-[800px] -z-10 pointer-events-none"></div>
      
      <main className="max-w-7xl mx-auto px-8 py-12 relative z-10">
        <header className="flex justify-between items-center mb-12 border-b border-indigo-900/30 pb-6">
          <div className="flex flex-col">
            <div className="flex items-center gap-3 text-sm font-medium text-slate-400 mb-2 hover:text-cyan-400 transition-colors">
              <Link href="/">← Back to Dashboard</Link>
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400 drop-shadow-sm pb-1">
              Endpoints Management
            </h1>
          </div>
          <button className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all font-medium shadow-[0_0_20px_rgba(79,70,229,0.3)] text-sm flex items-center gap-2">
            Enroll New Device
          </button>
        </header>

        <section className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-400">
              <thead className="bg-slate-900/80 text-xs uppercase font-medium text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4">Hardware ID</th>
                  <th className="px-6 py-4">Hostname</th>
                  <th className="px-6 py-4">Platform</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Threat Score</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {endpoints.map(ep => (
                  <tr key={ep.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-4 font-mono text-slate-200">{ep.id}</td>
                    <td className="px-6 py-4 font-mono text-indigo-300">{ep.hostname}</td>
                    <td className="px-6 py-4 text-slate-300">{ep.platform}</td>
                    <td className="px-6 py-4 flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${ep.status === 'Online' ? 'bg-emerald-500' : 'bg-slate-600'}`}></span>
                      {ep.status}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${ep.threatScore === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : ep.threatScore === 'Suspicious' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}`}>
                        {ep.threatScore}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="text-slate-500 hover:text-cyan-400 transition-colors font-medium">Details</button>
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

"use client";

import React from 'react';

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30 overflow-hidden relative">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-900/20 via-slate-950 to-slate-950 h-[800px] -z-10 pointer-events-none"></div>
      
      <main className="max-w-7xl mx-auto px-8 py-12 relative z-10">
        <header className="flex justify-between items-center mb-16">
          <div>
            <h1 className="text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600 drop-shadow-sm pb-1">
              AfterSec Command
            </h1>
            <p className="text-slate-400 mt-2 text-xs uppercase tracking-[0.2em] font-medium">Enterprise Security Matrix</p>
          </div>
          <div className="flex gap-4">
            <button className="px-5 py-2.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-all font-medium text-sm backdrop-blur-md flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
              Refresh Telemetry
            </button>
            <button className="px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] text-sm flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
              Global Lockdown
            </button>
          </div>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
          <StatCard title="Active Endpoints" value="1,204" trend="+12" />
          <StatCard title="UEBA Anomalies" value="3" alert={true} />
          <StatCard title="Total Telemetry" value="842.1M" />
          <StatCard title="Policies Enforced" value="100%" />
        </div>

        <section className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl">
          <div className="p-6 border-b border-slate-800 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-slate-100">Live Endpoint Matrix</h2>
            <div className="flex gap-2 items-center text-sm font-medium text-cyan-500">
               <span className="flex h-2.5 w-2.5 relative mr-2">
                 <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                 <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
               </span>
               Listening
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-400">
              <thead className="bg-slate-900/50 text-xs uppercase font-medium text-slate-500">
                <tr>
                  <th className="px-6 py-4">Hardware ID</th>
                  <th className="px-6 py-4">Platform</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Threat Score</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                <EndpointRow hw="HW-MACBOOK-PRO-9X" platform="macOS 14.2" status="Online" score="Safe" />
                <EndpointRow hw="HW-UBUNTU-SERV-01" platform="Linux 6.5" status="Online" score="Safe" />
                <EndpointRow hw="HW-WIN11-ENG-04" platform="Windows 11" status="Lost" score="Critical" alert={true} />
                <EndpointRow hw="HW-MACBOOK-AIR-22" platform="macOS 14.1" status="Offline" score="Suspicious" warn={true} />
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

function StatCard({ title, value, alert, trend }: { title: string, value: string, alert?: boolean, trend?: string }) {
  return (
    <div className={`p-6 rounded-2xl border backdrop-blur-md transition-all duration-300 hover:-translate-y-1 ${alert ? 'bg-red-950/20 border-red-900/50 shadow-[0_0_15px_rgba(153,27,27,0.2)]' : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:shadow-lg hover:shadow-cyan-900/10'}`}>
      <h3 className="text-slate-400 text-xs uppercase tracking-wider font-semibold mb-2">{title}</h3>
      <div className="flex items-end justify-between">
        <span className={`text-3xl font-bold ${alert ? 'text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]' : 'text-slate-100'}`}>{value}</span>
        {trend && <span className="text-cyan-400 text-sm font-medium">{trend}</span>}
      </div>
    </div>
  );
}

function EndpointRow({ hw, platform, status, score, alert, warn }: { hw: string, platform: string, status: string, score: string, alert?: boolean, warn?: boolean }) {
  return (
    <tr className="hover:bg-slate-800/30 transition-colors group">
      <td className="px-6 py-4 font-mono text-slate-200">{hw}</td>
      <td className="px-6 py-4 text-slate-300">{platform}</td>
      <td className="px-6 py-4 flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${status === 'Online' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-slate-600'}`}></span>
        {status}
      </td>
      <td className="px-6 py-4">
        <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${alert ? 'bg-red-500/10 text-red-400 border border-red-500/20' : warn ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}`}>
          {score}
        </span>
      </td>
      <td className="px-6 py-4 text-right">
        <button className="text-slate-500 hover:text-cyan-400 transition-colors px-2 font-medium">
          View
        </button>
        {alert && (
          <button className="text-red-400 hover:text-red-300 transition-colors px-2 ml-2 font-medium">
            Wipe Device
          </button>
        )}
      </td>
    </tr>
  );
}

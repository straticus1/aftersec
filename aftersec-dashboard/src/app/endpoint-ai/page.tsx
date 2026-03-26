"use client";

import React from 'react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { BrainCircuit, Activity, LineChart, Server, Zap, HardDrive } from 'lucide-react';

const mockEndpoints = [
  { id: 'ep1', hostname: 'fin-macbook-pro', status: 'enforcing', score: 99.8, anomalyDrift: 0.02, lastTraining: '2 hours ago', architecture: 'Apple M3 Max' },
  { id: 'ep2', hostname: 'dev-win-01', status: 'training', score: 45.1, anomalyDrift: null, lastTraining: 'In Progress...', architecture: 'Intel x86 Core i9' },
  { id: 'ep3', hostname: 'exec-mac-air', status: 'observing', score: 12.0, anomalyDrift: null, lastTraining: 'N/A (Collecting)', architecture: 'Apple M2' },
  { id: 'ep4', hostname: 'hr-imac-24', status: 'enforcing', score: 98.5, anomalyDrift: 1.20, lastTraining: '14 mins ago', architecture: 'Apple M1' },
  { id: 'ep5', hostname: 'eng-linux-srv', status: 'observing', score: 8.5, anomalyDrift: null, lastTraining: 'N/A (Collecting)', architecture: 'AMD EPYC' },
];

export default function EndpointAIPage() {
  const { currentTenant } = useTenant();

  return (
    <div className="min-h-screen relative p-8">
      <header className="mb-10">
        <h1 className="text-3xl font-extrabold tracking-tight text-white mb-2 flex items-center gap-3">
          <BrainCircuit className="h-8 w-8 text-indigo-400" />
          Endpoint AI (Local Behavioral Learning)
        </h1>
        <p className="text-gray-400 text-sm font-medium leading-relaxed max-w-4xl">
          Track the local anomaly detection models being trained directly on your endpoints. 
          AfterSec utilizes local on-device hardware (e.g., Apple Neural Engine) to compress user behavior into hyper-personalized neural baselines, catching zero-days before they mutate.
        </p>
      </header>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-xs font-bold uppercase tracking-wider mb-1">Enforcing Models</p>
            <p className="text-3xl font-black text-emerald-400">2</p>
          </div>
          <div className="h-12 w-12 rounded-full bg-emerald-500/10 flex items-center justify-center">
            <Activity className="h-6 w-6 text-emerald-400" />
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-xs font-bold uppercase tracking-wider mb-1">Actively Training</p>
            <p className="text-3xl font-black text-amber-400">1</p>
          </div>
          <div className="h-12 w-12 rounded-full bg-amber-500/10 flex items-center justify-center">
            <Zap className="h-6 w-6 text-amber-400" />
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-xs font-bold uppercase tracking-wider mb-1">Observing (Data Collection)</p>
            <p className="text-3xl font-black text-indigo-400">2</p>
          </div>
          <div className="h-12 w-12 rounded-full bg-indigo-500/10 flex items-center justify-center">
            <LineChart className="h-6 w-6 text-indigo-400" />
          </div>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-gray-800/50 text-xs uppercase font-medium text-gray-500">
              <tr>
                <th className="px-6 py-4">Endpoint</th>
                <th className="px-6 py-4">Hardware Accl.</th>
                <th className="px-6 py-4">Learning Phase</th>
                <th className="px-6 py-4">Model Confidence</th>
                <th className="px-6 py-4">Last Epoch</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {mockEndpoints.map((ep) => (
                <tr key={ep.id} className="hover:bg-gray-800/80 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-gray-500" />
                      <span className="font-bold text-gray-200">{ep.hostname}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-1.5 font-mono text-xs">
                       <HardDrive className="h-3.5 w-3.5 text-gray-500" />
                       <span className={ep.architecture.includes('Apple') ? 'text-blue-400' : 'text-gray-400'}>
                         {ep.architecture}
                       </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 w-max ${
                      ep.status === 'enforcing' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.1)]' : 
                      ep.status === 'training' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 
                      'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                    }`}>
                      {ep.status === 'enforcing' && <ShieldCheckIcon />}
                      {ep.status === 'training' && <Zap className="w-4 h-4" />}
                      {ep.status === 'observing' && <LineChart className="w-4 h-4" />}
                      {ep.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-24 bg-gray-800 rounded-full h-2 overflow-hidden border border-gray-700">
                        <div 
                          className={`h-full ${ep.status === 'enforcing' ? 'bg-emerald-500' : ep.status === 'training' ? 'bg-amber-500' : 'bg-indigo-500'}`} 
                          style={{ width: `${ep.score}%` }}
                        ></div>
                      </div>
                      <span className="font-mono text-xs font-bold text-gray-300">{ep.score}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-gray-500">
                    {ep.lastTraining}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-indigo-400 hover:text-white transition-colors font-semibold text-xs border border-indigo-500/30 bg-indigo-500/10 hover:bg-indigo-500/30 px-3 py-1.5 rounded">
                      Force Retrain
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function ShieldCheckIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>
  );
}

"use client";

import React from 'react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react';

const frameworks = [
  { name: 'CIS Benchmarks', score: 94, status: 'passing' },
  { name: 'HIPAA', score: 88, status: 'warning' },
  { name: 'SOC 2 Type II', score: 100, status: 'passing' },
  { name: 'ISO 27001', score: 72, status: 'failing' },
];

const checks = [
  { id: 1, policy: 'Ensure SSH root login is disabled', framework: 'CIS 5.2.3', status: 'passed' },
  { id: 2, policy: 'Ensure firewall is active', framework: 'CIS 3.5.1', status: 'passed' },
  { id: 3, policy: 'Ensure disk encryption is enabled', framework: 'SOC 2, HIPAA', status: 'passed' },
  { id: 4, policy: 'Ensure audit logging is configured', framework: 'ISO 27001', status: 'failed' },
  { id: 5, policy: 'Ensure inactive sessions timeout', framework: 'HIPAA 164.312(a)(2)(iii)', status: 'warning' },
];

export default function CompliancePage() {
  const { currentTenant } = useTenant();

  return (
    <div className="min-h-screen relative p-8">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/10 via-gray-950 to-gray-950 h-[800px] -z-10 pointer-events-none"></div>

      <header className="mb-10">
        <h1 className="text-3xl font-extrabold tracking-tight text-white pb-1">
          Compliance Overview
        </h1>
        <p className="text-gray-400 mt-1 text-sm font-medium">
          Tenant: <span className="text-indigo-400 font-semibold">{currentTenant?.name}</span>
        </p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
        {frameworks.map((fw) => (
          <div key={fw.name} className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
            <h3 className="text-gray-400 text-sm font-semibold mb-3">{fw.name}</h3>
            <div className="flex items-end justify-between">
              <span className="text-3xl font-bold text-white">{fw.score}%</span>
              {fw.status === 'passing' ? <CheckCircle className="text-emerald-500 h-6 w-6" /> :
               fw.status === 'warning' ? <AlertTriangle className="text-amber-500 h-6 w-6" /> :
               <XCircle className="text-red-500 h-6 w-6" />}
            </div>
            <div className="w-full bg-gray-800 mt-4 rounded-full h-1.5">
              <div 
                className={`h-1.5 rounded-full ${fw.score >= 90 ? 'bg-emerald-500' : fw.score >= 80 ? 'bg-amber-500' : 'bg-red-500'}`}
                style={{ width: `${fw.score}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>

      <section className="bg-gray-900 border border-gray-800 rounded-xl shadow-xl overflow-hidden">
        <div className="p-6 border-b border-gray-800">
           <h2 className="text-lg font-semibold text-white">Detailed Policy Checks</h2>
        </div>
        <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-gray-800/50 text-xs uppercase font-medium text-gray-500">
              <tr>
                <th className="px-6 py-4">Policy Description</th>
                <th className="px-6 py-4">Framework Mapping</th>
                <th className="px-6 py-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {checks.map((check) => (
                <tr key={check.id} className="hover:bg-gray-800/80 transition-colors">
                  <td className="px-6 py-4 text-gray-300 font-medium">{check.policy}</td>
                  <td className="px-6 py-4 text-indigo-300">{check.framework}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                      check.status === 'failed' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                      check.status === 'warning' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 
                      'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {check.status.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
        </table>
      </section>
    </div>
  );
}

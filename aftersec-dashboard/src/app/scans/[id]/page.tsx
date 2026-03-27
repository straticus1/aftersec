'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { getScanDetail } from '@/lib/api';

type Finding = {
  id: string;
  category: string;
  name: string;
  description: string;
  severity: 'low' | 'med' | 'high' | 'critical';
  currentVal: string;
  expectedVal: string;
  passed: boolean;
  remediationScript?: string;
};

type ScanDetail = {
  id: string;
  endpointId: string;
  timestamp: string;
  status: string;
  findings: Finding[];
};

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [activeTab, setActiveTab] = useState<'all' | 'critical' | 'high' | 'med' | 'low'>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const fetchScan = async () => {
      const data = await getScanDetail(scanId);
      setScan(data);
    };
    fetchScan();
  }, [scanId]);

  if (!scan) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 font-sans flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-fuchsia-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'high': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'med': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'low': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const filterFindings = (findings: Finding[]) => {
    if (activeTab === 'all') return findings;
    return findings.filter(f => f.severity === activeTab);
  };

  const filteredFindings = filterFindings(scan.findings);

  const getCounts = () => {
    return {
      all: scan.findings.length,
      critical: scan.findings.filter(f => f.severity === 'critical').length,
      high: scan.findings.filter(f => f.severity === 'high').length,
      med: scan.findings.filter(f => f.severity === 'med').length,
      low: scan.findings.filter(f => f.severity === 'low').length,
    };
  };

  const counts = getCounts();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-purple-500/30 overflow-hidden relative">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-fuchsia-900/20 via-slate-950 to-slate-950 h-[800px] -z-10 pointer-events-none"></div>

      <main className="max-w-7xl mx-auto px-8 py-12 relative z-10">
        <header className="flex justify-between items-center mb-8 border-b border-fuchsia-900/30 pb-6">
          <div className="flex flex-col">
            <div className="flex items-center gap-3 text-sm font-medium text-slate-400 mb-2 hover:text-fuchsia-400 transition-colors">
              <Link href="/scans">← Back to Scans</Link>
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-fuchsia-400 to-purple-600 drop-shadow-sm pb-1">
              Scan Details
            </h1>
            <div className="text-sm text-slate-400 mt-2">
              <span className="font-mono">{scan.endpointId}</span> • {new Date(scan.timestamp).toLocaleString()}
            </div>
          </div>
        </header>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-slate-800">
          {(['all', 'critical', 'high', 'med', 'low'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-6 py-3 font-medium text-sm transition-all ${
                activeTab === tab
                  ? 'text-fuchsia-400 border-b-2 border-fuchsia-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)} {counts[tab] > 0 && `(${counts[tab]})`}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Findings List */}
          <div className="lg:col-span-2">
            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl">
              <div className="divide-y divide-slate-800/50">
                {filteredFindings.length === 0 ? (
                  <div className="px-6 py-12 text-center text-slate-400">
                    No {activeTab !== 'all' ? activeTab : ''} findings found
                  </div>
                ) : (
                  filteredFindings.map((finding) => (
                    <button
                      key={finding.id}
                      onClick={() => setSelectedFinding(finding)}
                      className={`w-full px-6 py-4 text-left hover:bg-slate-800/30 transition-colors ${
                        selectedFinding?.id === finding.id ? 'bg-slate-800/50' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${getSeverityColor(finding.severity)}`}>
                              {finding.severity.toUpperCase()}
                            </span>
                            <span className="text-xs text-slate-500">{finding.category}</span>
                          </div>
                          <h3 className="text-lg font-semibold text-slate-200 mb-1">{finding.name}</h3>
                          <p className="text-sm text-slate-400 line-clamp-2">{finding.description}</p>
                        </div>
                        <svg className="w-5 h-5 text-slate-600 flex-shrink-0 mt-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Finding Details Panel */}
          <div className="lg:col-span-1">
            {selectedFinding ? (
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl sticky top-4">
                <div className="p-6 border-b border-slate-800">
                  <h2 className="text-xl font-bold text-slate-200 mb-2">Finding Details</h2>
                  <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${getSeverityColor(selectedFinding.severity)}`}>
                    {selectedFinding.severity.toUpperCase()}
                  </span>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Name</h3>
                    <p className="text-slate-200">{selectedFinding.name}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Category</h3>
                    <p className="text-slate-200">{selectedFinding.category}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Description</h3>
                    <p className="text-slate-200">{selectedFinding.description}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Current Value</h3>
                    <p className="text-red-400 font-mono text-sm">{selectedFinding.currentVal}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-400 mb-1">Expected Value</h3>
                    <p className="text-emerald-400 font-mono text-sm">{selectedFinding.expectedVal}</p>
                  </div>
                  {selectedFinding.remediationScript && (
                    <div>
                      <h3 className="text-sm font-semibold text-slate-400 mb-1">Remediation</h3>
                      <div className="bg-slate-950 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto">
                        {selectedFinding.remediationScript}
                      </div>
                      <button className="mt-3 w-full px-4 py-2 rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 text-white transition-all font-medium shadow-[0_0_20px_rgba(192,38,211,0.3)] text-sm">
                        Apply Remediation
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-2xl p-12 text-center text-slate-400">
                <svg className="w-16 h-16 mx-auto mb-4 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p>Select a finding to view details</p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

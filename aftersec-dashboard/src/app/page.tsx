"use client";

import React from 'react';
import PostureTrendChart from '@/components/charts/PostureTrendChart';
import ThreatDistributionChart from '@/components/charts/ThreatDistributionChart';
import { useRealTimeScans } from '@/lib/hooks/useRealTimeScans';
import { useTenant } from '@/lib/contexts/TenantContext';
import { History } from 'lucide-react';
import RollbackModal from '@/components/RollbackModal';
import ExportMenu from '@/components/ExportMenu';
import FilterBar from '@/components/FilterBar';
import { useFilters, filterHelpers } from '@/lib/hooks/useFilters';

export default function Home() {
  const { currentTenant } = useTenant();
  const { scans } = useRealTimeScans();
  const [rollbackEndpoint, setRollbackEndpoint] = React.useState<string | null>(null);

  // Setup filtering
  const {
    filters,
    filteredData,
    updateFilter,
    clearFilters,
    savedPresets,
    applyPreset,
    savePreset,
    hasActiveFilters,
    resultCount,
    totalCount,
  } = useFilters({
    data: scans,
    filterFn: (scan, filters) => {
      // Search filter
      if (filters.search && !filterHelpers.matchesSearch(
        `${scan.endpoint} ${scan.details}`,
        filters.search
      )) {
        return false;
      }

      // Status filter
      if (!filterHelpers.matchesMultiSelect(scan.status, filters.status)) {
        return false;
      }

      // Time range filter
      if (!filterHelpers.matchesTimeRange(scan.timestamp, filters.timeRange)) {
        return false;
      }

      return true;
    },
  });

  // Prepare PDF report sections
  const pdfSections = [
    {
      heading: 'Executive Summary',
      content: [
        `Active Endpoints: 1,204 (+12 from last week)`,
        `UEBA Anomalies Detected: 3 (2 high severity, 1 medium)`,
        `Total Telemetry Events: 842.1M events processed`,
        `Overall Security Score: 92/100 (+2 improvement)`,
      ],
    },
    {
      heading: 'Recent Security Scans',
      content: scans.slice(0, 5).map((scan) =>
        `${scan.endpoint} - ${scan.status.toUpperCase()}: ${scan.details} (${new Date(scan.timestamp).toLocaleString()})`
      ),
    },
    {
      heading: 'Recommendations',
      content: [
        'Address 3 UEBA anomalies identified in production environment',
        'Review SSH configuration on dev-server-01 for outdated keys',
        'Disable root login on prod-db-01 to meet compliance requirements',
        'Continue monitoring endpoints showing recent configuration drift',
      ],
    },
  ];

  return (
    <div className="min-h-screen relative p-8 selection:bg-cyan-500/30">
      <div className="absolute top-0 -inset-x-20 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/20 via-gray-950 to-gray-950 h-[800px] -z-10 pointer-events-none"></div>
      
      <header className="flex justify-between items-center mb-10">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white pb-1">
            Dashboard Overview
          </h1>
          <p className="text-gray-400 mt-1 text-sm font-medium">
            Organization: <span className="text-indigo-400 font-semibold">{currentTenant?.name || 'Loading...'}</span>
          </p>
        </div>
        <div className="flex gap-4">
          <button className="px-5 py-2.5 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 transition-all font-medium text-sm text-gray-300 flex items-center gap-2">
            Refresh Data
          </button>
          <ExportMenu
            data={scans.slice(0, 5).map((scan) => ({
              timestamp: new Date(scan.timestamp).toLocaleString(),
              endpoint: scan.endpoint,
              status: scan.status,
              details: scan.details,
            }))}
            filename="aftersec-dashboard-report"
            pdfTitle={`AfterSec Security Dashboard - ${currentTenant?.name || 'Organization'}`}
            pdfSections={pdfSections}
          />
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatCard title="Active Endpoints" value="1,204" trend="+12" />
        <StatCard title="UEBA Anomalies" value="3" alert={true} />
        <StatCard title="Total Telemetry" value="842.1M" />
        <StatCard title="Overall Score" value="92/100" trend="+2" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl">
          <h2 className="text-lg font-semibold text-white mb-6">Security Posture Trend</h2>
          <PostureTrendChart />
        </section>
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl">
          <h2 className="text-lg font-semibold text-white mb-6">Threat Distribution</h2>
          <ThreatDistributionChart />
        </section>
      </div>

      <FilterBar
        filters={filters}
        onFilterChange={updateFilter}
        onClearFilters={clearFilters}
        savedPresets={savedPresets}
        onApplyPreset={applyPreset}
        onSavePreset={savePreset}
        hasActiveFilters={hasActiveFilters}
        resultCount={resultCount}
        totalCount={totalCount}
      />

      <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-6 border-b border-gray-800 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-white">Live Real-Time Scans</h2>
          <div className="flex gap-2 items-center text-sm font-medium text-indigo-400">
             <span className="flex h-2 w-2 relative mr-1">
               <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
               <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
             </span>
             Receiving events...
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-gray-800/50 text-xs uppercase font-medium text-gray-500">
              <tr>
                <th className="px-6 py-4">Time</th>
                <th className="px-6 py-4">Endpoint</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Details</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {filteredData.slice(0, 10).map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-800/80 transition-colors group">
                  <td className="px-6 py-4 whitespace-nowrap">{new Date(scan.timestamp).toLocaleTimeString()}</td>
                  <td className="px-6 py-4 font-mono text-gray-300">{scan.endpoint}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                      scan.status === 'failed' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                      scan.status === 'warning' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 
                      'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {scan.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-300">{scan.details}</td>
                  <td className="px-6 py-4 text-right flex justify-end">
                    <button 
                      onClick={() => setRollbackEndpoint(scan.endpoint)}
                      className="text-gray-500 hover:text-indigo-400 transition-colors font-semibold text-sm flex items-center gap-1"
                    >
                      <History className="h-4 w-4" /> Rollback
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      
      <RollbackModal 
        isOpen={!!rollbackEndpoint} 
        onClose={() => setRollbackEndpoint(null)} 
        endpointName={rollbackEndpoint || ''} 
      />
    </div>
  );
}

function StatCard({ title, value, alert, trend }: { title: string, value: string, alert?: boolean, trend?: string }) {
  return (
    <div className={`p-6 rounded-xl border transition-all duration-300 hover:-translate-y-1 ${alert ? 'bg-red-950/20 border-red-900/50 shadow-[0_0_15px_rgba(153,27,27,0.1)]' : 'bg-gray-900 border-gray-800 hover:border-gray-700 hover:shadow-lg hover:shadow-indigo-900/5'}`}>
      <h3 className="text-gray-400 text-xs uppercase tracking-wider font-semibold mb-2">{title}</h3>
      <div className="flex items-end justify-between">
        <span className={`text-3xl font-bold ${alert ? 'text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.3)]' : 'text-white'}`}>{value}</span>
        {trend && <span className="text-indigo-400 text-sm font-medium">{trend}</span>}
      </div>
    </div>
  );
}

'use client';

import { useState } from 'react';
import { AlertTriangle, Shield, Eye, Database, ChevronRight } from 'lucide-react';

interface DarkWebAlert {
  id: string;
  type: 'breached_credential' | 'malicious_hash' | 'c2_connection' | 'dark_web_mention';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  timestamp: string;
  endpoint?: string;
  intel_source: string;
}

// Mock data - in production this would come from the backend API
const mockAlerts: DarkWebAlert[] = [
  {
    id: 'dw-1',
    type: 'breached_credential',
    severity: 'high',
    title: 'Employee Credentials in Data Breach',
    description: 'admin@company.com found in LinkedIn breach (2023)',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    intel_source: 'DarkAPI.io',
  },
  {
    id: 'dw-2',
    type: 'c2_connection',
    severity: 'critical',
    title: 'C2 Server Connection Detected',
    description: 'Endpoint connected to known APT28 infrastructure (185.220.101.42)',
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    endpoint: 'prod-api-02',
    intel_source: 'DarkAPI.io',
  },
  {
    id: 'dw-3',
    type: 'dark_web_mention',
    severity: 'medium',
    title: 'Company Mentioned on Dark Web Forum',
    description: 'Organization discussed in RaidForums with 87% relevance score',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    intel_source: 'DarkAPI.io',
  },
  {
    id: 'dw-4',
    type: 'malicious_hash',
    severity: 'critical',
    title: 'Known Malware Hash Detected',
    description: 'Process hash matches known Emotet variant from dark web samples',
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    endpoint: 'dev-server-01',
    intel_source: 'DarkAPI.io',
  },
];

export default function DarkWebAlertsWidget() {
  const [alerts] = useState<DarkWebAlert[]>(mockAlerts);

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'breached_credential':
        return <Shield className="h-5 w-5" />;
      case 'c2_connection':
        return <AlertTriangle className="h-5 w-5" />;
      case 'dark_web_mention':
        return <Eye className="h-5 w-5" />;
      case 'malicious_hash':
        return <Database className="h-5 w-5" />;
      default:
        return <AlertTriangle className="h-5 w-5" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'medium':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-xl overflow-hidden">
      <div className="p-6 border-b border-gray-800 bg-gradient-to-br from-purple-900/20 to-gray-900">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Eye className="h-5 w-5 text-purple-400" />
            Dark Web Intelligence
          </h2>
          <span className="px-2.5 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-full text-xs font-semibold">
            LIVE
          </span>
        </div>
        <p className="text-xs text-gray-400">
          Correlated threats from dark web monitoring via DarkAPI.io
        </p>
      </div>

      <div className="p-4">
        {alerts.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Eye className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p className="text-sm">No dark web threats detected</p>
          </div>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg hover:bg-gray-800 hover:border-purple-500/30 transition-all group cursor-pointer"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg border ${getSeverityColor(alert.severity)}`}>
                    {getTypeIcon(alert.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <h3 className="text-sm font-semibold text-white line-clamp-1">
                        {alert.title}
                      </h3>
                      <span className="text-xs text-gray-500 whitespace-nowrap">
                        {formatTimestamp(alert.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 line-clamp-2 mb-2">
                      {alert.description}
                    </p>
                    <div className="flex items-center justify-between">
                      <div className="flex gap-2 text-xs">
                        {alert.endpoint && (
                          <span className="px-2 py-0.5 bg-gray-700/50 text-gray-300 rounded font-mono">
                            {alert.endpoint}
                          </span>
                        )}
                        <span className="px-2 py-0.5 bg-purple-500/10 text-purple-400 rounded font-mono">
                          {alert.intel_source}
                        </span>
                      </div>
                      <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-purple-400 transition-colors" />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="p-4 border-t border-gray-800 bg-gray-900/50">
        <div className="flex items-center justify-between text-xs">
          <span className="text-gray-500">
            Last updated: {formatTimestamp(alerts[0]?.timestamp || new Date().toISOString())}
          </span>
          <button className="text-purple-400 hover:text-purple-300 font-semibold transition-colors">
            View All Threats →
          </button>
        </div>
      </div>
    </div>
  );
}

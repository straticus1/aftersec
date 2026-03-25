'use client';

import { useState, useEffect } from 'react';
import { useSettings } from '@/lib/contexts/SettingsContext';

export interface ScanResult {
  id: string;
  timestamp: string;
  endpoint: string;
  status: 'passed' | 'failed' | 'warning';
  details: string;
}

const initialScans: ScanResult[] = [
  { id: 'scan-1', timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(), endpoint: 'macbook-pro-ryan', status: 'passed', details: 'Routine system scan completed. No issues.' },
  { id: 'scan-2', timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(), endpoint: 'dev-server-01', status: 'warning', details: 'Outdated SSH keys detected.' },
  { id: 'scan-3', timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(), endpoint: 'prod-db-01', status: 'failed', details: 'Root login enabled in sshd_config.' },
];

export function useRealTimeScans() {
  const [scans, setScans] = useState<ScanResult[]>(initialScans);
  const { useMockData } = useSettings();

  useEffect(() => {
    // If not using mock data, you would initialize a true WebSocket here:
    // const ws = new WebSocket('wss://api.aftersec.io/scans');
    // ws.onmessage = (event) => setScans(prev => [JSON.parse(event.data), ...prev]);
    // return () => ws.close();

    if (!useMockData) {
      setScans([]); // Clear scans if connected to real data (which is empty right now)
      return; 
    }

    // Simulating a WebSocket or SSE connection that pushes a new scan every 12 seconds
    const interval = setInterval(() => {
      const endpoints = ['macbook-pro-ryan', 'dev-server-01', 'prod-db-01', 'qa-server-04', 'analyst-workstation'];
      const statuses: ('passed' | 'warning' | 'failed')[] = ['passed', 'passed', 'passed', 'warning', 'failed'];
      const detailsMap = {
        passed: 'Routine check cleared.',
        warning: 'Configuration drift detected minus critical policy.',
        failed: 'High severity vulnerability signature matched.',
      };

      const randomEndpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
      const randomStatus = statuses[Math.floor(Math.random() * statuses.length)];

      const newScan: ScanResult = {
        id: `scan-${Date.now()}`,
        timestamp: new Date().toISOString(),
        endpoint: randomEndpoint,
        status: randomStatus,
        details: detailsMap[randomStatus],
      };

      setScans((prev) => [newScan, ...prev].slice(0, 50)); // Keep last 50
    }, 12000);

    return () => clearInterval(interval);
  }, [useMockData]);

  return { scans };
}

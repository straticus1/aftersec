const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1';

type Endpoint = {
  id: string;
  hostname: string;
  platform: string;
  status: string;
  threatScore: string;
};

type ServerEndpoint = {
  id?: string;
  hostname?: string;
  platform?: string;
  platform_version?: string;
  enrollment_status?: string;
  posture?: { checks?: { passed?: boolean }[] };
};

function mapServerEndpoint(row: ServerEndpoint): Endpoint | null {
  if (!row.id || !row.hostname || !row.platform || !row.enrollment_status) {
    return null;
  }
  const failed = Array.isArray(row.posture?.checks) && row.posture.checks.some((check) => check.passed === false);
  return {
    id: row.id,
    hostname: row.hostname,
    platform: row.platform_version ? `${row.platform} ${row.platform_version}` : row.platform,
    status: row.enrollment_status,
    threatScore: row.enrollment_status === 'inventory' ? (failed ? 'Check failed' : 'Reported') : 'Safe',
  };
}

// Sample rows stay visible only when the server has no endpoints yet.
export async function getEndpoints(): Promise<Endpoint[]> {
  try {
    const res = await fetch(`${API_URL}/endpoints`, { cache: 'no-store' });
    if (!res.ok) throw new Error('API error');
    const body: unknown = await res.json();
    if (Array.isArray(body)) {
      const mapped = body.map((row) => mapServerEndpoint(row as ServerEndpoint)).filter((row): row is Endpoint => row !== null);
      if (mapped.length > 0) return mapped;
    }
    return [
      { id: 'HW-MACBOOK-PRO-9X', hostname: 'ryan-mbp', platform: 'macOS 14.2', status: 'Online', threatScore: 'Safe' },
      { id: 'HW-UBUNTU-SERV-01', hostname: 'prod-backend-1', platform: 'Linux 6.5', status: 'Online', threatScore: 'Safe' },
      { id: 'HW-WIN11-ENG-04', hostname: 'eng-workstation', platform: 'Windows 11', status: 'Lost', threatScore: 'Critical' },
      { id: 'HW-MACBOOK-AIR-22', hostname: 'guest-mac', platform: 'macOS 14.1', status: 'Offline', threatScore: 'Suspicious' }
    ];
  } catch (error) {
    return [];
  }
}

type Scan = {
  id: string;
  endpointId: string;
  timestamp: string;
  status: string;
  findingsCount: number;
};

export async function getScans(): Promise<Scan[]> {
  try {
    const res = await fetch(`${API_URL}/scans`, { cache: 'no-store' });
    if (!res.ok) throw new Error('API error');
    return [
      { id: 'scan-1', endpointId: 'HW-MACBOOK-PRO-9X', timestamp: new Date().toISOString(), status: 'completed', findingsCount: 0 },
      { id: 'scan-2', endpointId: 'HW-WIN11-ENG-04', timestamp: new Date(Date.now() - 3600000).toISOString(), status: 'completed', findingsCount: 12 },
    ];
  } catch (error) {
    return [];
  }
}

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

export async function getScanDetail(scanId: string): Promise<ScanDetail | null> {
  try {
    const res = await fetch(`${API_URL}/scans/${scanId}`, { cache: 'no-store' });
    if (!res.ok) throw new Error('API error');
    // Mock data
    if (scanId === 'scan-2') {
      return {
        id: 'scan-2',
        endpointId: 'HW-WIN11-ENG-04',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        status: 'completed',
        findings: [
          {
            id: '1',
            category: 'Network Security',
            name: 'SSH Password Auth Enabled',
            description: 'SSH password authentication is enabled, making brute-force attacks possible',
            severity: 'high',
            currentVal: 'enabled',
            expectedVal: 'disabled',
            passed: false,
            remediationScript: 'sed -i \'\' \'s/^#*PasswordAuthentication.*/PasswordAuthentication no/\' /etc/ssh/sshd_config'
          },
          {
            id: '2',
            category: 'System Integrity',
            name: 'FileVault Disabled',
            description: 'Full disk encryption is not enabled',
            severity: 'critical',
            currentVal: 'off',
            expectedVal: 'on',
            passed: false
          },
          {
            id: '3',
            category: 'Malware Detection',
            name: 'Crypto Miner Detected: xmrig',
            description: 'Known cryptocurrency mining process found: /usr/local/bin/xmrig',
            severity: 'critical',
            currentVal: 'running',
            expectedVal: 'not present',
            passed: false,
            remediationScript: 'kill -9 1234'
          },
          {
            id: '4',
            category: 'Kernel Tuning',
            name: 'TCP Blackhole Not Configured',
            description: 'TCP blackhole should be set to 2 for better security',
            severity: 'low',
            currentVal: '0',
            expectedVal: '2',
            passed: false
          },
          {
            id: '5',
            category: 'File Permissions',
            name: 'World-Writable Files Check',
            description: 'File permission scanning completed',
            severity: 'med',
            currentVal: 'checked',
            expectedVal: 'clean',
            passed: false
          }
        ]
      };
    }
    return null;
  } catch (error) {
    return null;
  }
}

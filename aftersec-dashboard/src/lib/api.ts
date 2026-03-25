const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080/api/v1';

type Endpoint = {
  id: string;
  hostname: string;
  platform: string;
  status: string;
  threatScore: string;
};

// Currently mocking response since backend uses stubs
export async function getEndpoints(): Promise<Endpoint[]> {
  try {
    const res = await fetch(`${API_URL}/endpoints`, { cache: 'no-store' });
    if (!res.ok) throw new Error('API error');
    // For now we map an empty array to some dummy data to showcase UI since backend is stubbed
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

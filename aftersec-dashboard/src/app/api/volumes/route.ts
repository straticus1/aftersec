import { NextResponse } from 'next/server';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export async function GET() {
  try {
    // Call the Go backend API
    const response = await fetch(`${API_URL}/api/v1/darkscan/volumes`, {
      headers: {
        'Content-Type': 'application/json',
        // Add JWT token if available
        // 'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const data = await response.json();

    if (data.success && data.data && data.data.volumes) {
      return NextResponse.json({ success: true, volumes: data.data.volumes });
    } else {
      // Fallback to common macOS volumes if API call fails
      const volumes = [
        {
          path: '/',
          filesystem: 'apfs',
          mount_point: '/'
        },
        {
          path: '/System/Volumes/Data',
          filesystem: 'apfs',
          mount_point: '/System/Volumes/Data'
        }
      ];
      return NextResponse.json({ success: true, volumes });
    }
  } catch (error) {
    console.error('Failed to fetch volumes:', error);

    // Fallback to common volumes on error
    const volumes = [
      {
        path: '/',
        filesystem: 'apfs',
        mount_point: '/'
      }
    ];
    return NextResponse.json({ success: true, volumes });
  }
}

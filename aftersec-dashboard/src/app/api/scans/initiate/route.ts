import { NextRequest, NextResponse } from 'next/server';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { paths, scanType, profile } = body;

    if (!paths || !Array.isArray(paths) || paths.length === 0) {
      return NextResponse.json(
        { success: false, error: 'Paths array is required' },
        { status: 400 }
      );
    }

    // Determine which API endpoint to use
    let endpoint: string;
    let requestBody: any;

    if (paths.length === 1 && scanType === 'volume') {
      // Single volume scan
      endpoint = `${API_URL}/api/v1/darkscan/scan/volume`;
      requestBody = {
        path: paths[0],
        profile: profile || 'standard'
      };
    } else if (paths.length > 1) {
      // Multiple paths scan
      endpoint = `${API_URL}/api/v1/darkscan/scan/multiple`;
      requestBody = {
        paths: paths,
        profile: profile || 'standard',
        recursive: scanType === 'volume'
      };
    } else {
      // Single directory/file scan
      endpoint = `${API_URL}/api/v1/darkscan/scan/directory`;
      requestBody = {
        path: paths[0],
        recursive: true
      };
    }

    console.log('Initiating scan:', {
      endpoint,
      body: requestBody,
      timestamp: new Date().toISOString()
    });

    // Call the Go backend API
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Add JWT token if available
        // 'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(requestBody)
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error || `API returned ${response.status}`);
    }

    const scanId = `scan-${Date.now()}`;

    return NextResponse.json({
      success: true,
      scanId,
      status: 'initiated',
      message: `Scan initiated for ${paths.length} path(s)`,
      data: data.data
    });
  } catch (error) {
    console.error('Scan initiation error:', error);
    return NextResponse.json(
      { success: false, error: `Failed to initiate scan: ${error}` },
      { status: 500 }
    );
  }
}

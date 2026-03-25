import { format } from 'date-fns';

export interface ExportOptions {
  filename?: string;
  includeTimestamp?: boolean;
}

/**
 * Export data to CSV format
 */
export function exportToCSV<T extends Record<string, any>>(
  data: T[],
  options: ExportOptions = {}
): void {
  if (!data || data.length === 0) {
    console.warn('No data to export');
    return;
  }

  const { filename = 'export', includeTimestamp = true } = options;

  // Get headers from first object
  const headers = Object.keys(data[0]);

  // Create CSV content
  const csvContent = [
    headers.join(','),
    ...data.map((row) =>
      headers.map((header) => {
        const value = row[header];
        // Handle special characters and quotes
        const stringValue = String(value ?? '');
        return stringValue.includes(',') || stringValue.includes('"')
          ? `"${stringValue.replace(/"/g, '""')}"`
          : stringValue;
      }).join(',')
    ),
  ].join('\n');

  // Create and download blob
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const timestamp = includeTimestamp ? `_${format(new Date(), 'yyyy-MM-dd_HHmmss')}` : '';
  downloadBlob(blob, `${filename}${timestamp}.csv`);
}

/**
 * Export data to JSON format
 */
export function exportToJSON<T>(
  data: T,
  options: ExportOptions = {}
): void {
  const { filename = 'export', includeTimestamp = true } = options;

  const jsonContent = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
  const timestamp = includeTimestamp ? `_${format(new Date(), 'yyyy-MM-dd_HHmmss')}` : '';
  downloadBlob(blob, `${filename}${timestamp}.json`);
}

/**
 * Generate a PDF report (client-side)
 */
export function exportToPDF(
  title: string,
  sections: Array<{ heading: string; content: string | string[] }>,
  options: ExportOptions = {}
): void {
  const { filename = 'report', includeTimestamp = true } = options;

  // Create HTML content for PDF
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    @page {
      margin: 1in;
      size: letter;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      line-height: 1.6;
      color: #1f2937;
      max-width: 8.5in;
      margin: 0 auto;
    }
    .header {
      border-bottom: 3px solid #4f46e5;
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }
    .header h1 {
      margin: 0;
      color: #1f2937;
      font-size: 2rem;
    }
    .header .timestamp {
      color: #6b7280;
      font-size: 0.875rem;
      margin-top: 0.5rem;
    }
    .section {
      margin-bottom: 2rem;
      page-break-inside: avoid;
    }
    .section h2 {
      color: #4f46e5;
      font-size: 1.25rem;
      margin-bottom: 0.75rem;
      border-bottom: 1px solid #e5e7eb;
      padding-bottom: 0.5rem;
    }
    .section-content {
      color: #374151;
      font-size: 0.9375rem;
    }
    .section-content ul {
      margin: 0.5rem 0;
      padding-left: 1.5rem;
    }
    .footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid #e5e7eb;
      text-align: center;
      color: #9ca3af;
      font-size: 0.75rem;
    }
    @media print {
      body { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>${title}</h1>
    <div class="timestamp">Generated on ${format(new Date(), 'MMMM dd, yyyy \'at\' h:mm a')}</div>
  </div>
  ${sections.map((section) => `
    <div class="section">
      <h2>${section.heading}</h2>
      <div class="section-content">
        ${Array.isArray(section.content)
          ? `<ul>${section.content.map((item) => `<li>${item}</li>`).join('')}</ul>`
          : `<p>${section.content}</p>`
        }
      </div>
    </div>
  `).join('')}
  <div class="footer">
    AfterSec Enterprise Security Posture Management<br>
    Confidential - For Internal Use Only
  </div>
</body>
</html>
  `;

  // Create blob and download
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
  const timestamp = includeTimestamp ? `_${format(new Date(), 'yyyy-MM-dd_HHmmss')}` : '';

  // Open in new window for printing to PDF
  const printWindow = window.open('', '_blank');
  if (printWindow) {
    printWindow.document.write(htmlContent);
    printWindow.document.close();

    // Wait for content to load, then trigger print dialog
    printWindow.onload = () => {
      printWindow.print();
    };
  } else {
    // Fallback: download as HTML if popup blocked
    downloadBlob(blob, `${filename}${timestamp}.html`);
    alert('Please allow popups to print to PDF, or use the downloaded HTML file.');
  }
}

/**
 * Helper function to download a blob
 */
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

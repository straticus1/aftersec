'use client';

import { useState, useRef, useEffect } from 'react';
import { Download, FileText, FileSpreadsheet, FileJson, ChevronDown } from 'lucide-react';
import { exportToCSV, exportToJSON, exportToPDF } from '@/lib/utils/export';

interface ExportMenuProps {
  data: any[];
  filename: string;
  pdfTitle?: string;
  pdfSections?: Array<{ heading: string; content: string | string[] }>;
}

export default function ExportMenu({ data, filename, pdfTitle, pdfSections }: ExportMenuProps) {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const handleExport = (format: 'csv' | 'json' | 'pdf') => {
    switch (format) {
      case 'csv':
        exportToCSV(data, { filename });
        break;
      case 'json':
        exportToJSON(data, { filename });
        break;
      case 'pdf':
        if (pdfTitle && pdfSections) {
          exportToPDF(pdfTitle, pdfSections, { filename });
        } else {
          alert('PDF export not configured for this view');
        }
        break;
    }
    setIsOpen(false);
  };

  return (
    <div className="relative inline-block" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 transition-all font-medium text-sm text-gray-300"
      >
        <Download className="h-4 w-4" />
        Export
        <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-56 rounded-lg bg-gray-900 border border-gray-800 shadow-2xl z-50 overflow-hidden">
          <div className="p-2">
            <button
              onClick={() => handleExport('csv')}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition-colors text-left group"
            >
              <FileSpreadsheet className="h-5 w-5 text-green-400" />
              <div>
                <div className="text-sm font-medium text-gray-200 group-hover:text-white">
                  Export as CSV
                </div>
                <div className="text-xs text-gray-500">
                  For Excel and data analysis
                </div>
              </div>
            </button>

            <button
              onClick={() => handleExport('json')}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition-colors text-left group"
            >
              <FileJson className="h-5 w-5 text-blue-400" />
              <div>
                <div className="text-sm font-medium text-gray-200 group-hover:text-white">
                  Export as JSON
                </div>
                <div className="text-xs text-gray-500">
                  For programmatic access
                </div>
              </div>
            </button>

            {pdfTitle && pdfSections && (
              <button
                onClick={() => handleExport('pdf')}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition-colors text-left group"
              >
                <FileText className="h-5 w-5 text-red-400" />
                <div>
                  <div className="text-sm font-medium text-gray-200 group-hover:text-white">
                    Generate PDF Report
                  </div>
                  <div className="text-xs text-gray-500">
                    For compliance and audits
                  </div>
                </div>
              </button>
            )}
          </div>

          <div className="border-t border-gray-800 p-2">
            <div className="px-3 py-2 text-xs text-gray-500">
              <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono">
                ⌘
              </kbd>
              <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono ml-1">
                Shift
              </kbd>
              <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono ml-1">
                E
              </kbd>
              <span className="ml-2">to export</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

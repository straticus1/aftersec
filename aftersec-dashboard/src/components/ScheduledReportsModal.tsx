'use client';

import { useState } from 'react';
import { X, Plus, Trash2, Mail, Calendar, Clock } from 'lucide-react';

interface ScheduledReport {
  id: string;
  name: string;
  frequency: 'daily' | 'weekly' | 'monthly';
  format: 'pdf' | 'csv';
  recipients: string[];
  enabled: boolean;
}

export default function ScheduledReportsModal({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const [reports, setReports] = useState<ScheduledReport[]>([
    {
      id: '1',
      name: 'Weekly Security Summary',
      frequency: 'weekly',
      format: 'pdf',
      recipients: ['security@example.com'],
      enabled: true,
    },
    {
      id: '2',
      name: 'Daily Scan Results',
      frequency: 'daily',
      format: 'csv',
      recipients: ['ops@example.com', 'devops@example.com'],
      enabled: true,
    },
  ]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-gray-900 border border-gray-800 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-6 flex justify-between items-center">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <Calendar className="h-6 w-6 text-indigo-400" />
              Scheduled Reports
            </h2>
            <p className="text-sm text-gray-400 mt-1">
              Automate security report delivery to your team
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
            aria-label="Close"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {reports.map((report) => (
            <div
              key={report.id}
              className="bg-gray-800/50 border border-gray-700 rounded-lg p-5 hover:border-gray-600 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-white mb-2">{report.name}</h3>
                  <div className="flex flex-wrap gap-3 text-sm">
                    <span className="flex items-center gap-1.5 text-gray-400">
                      <Clock className="h-4 w-4" />
                      {report.frequency.charAt(0).toUpperCase() + report.frequency.slice(1)}
                    </span>
                    <span className="flex items-center gap-1.5 text-gray-400">
                      <Mail className="h-4 w-4" />
                      {report.recipients.length} recipient{report.recipients.length !== 1 ? 's' : ''}
                    </span>
                    <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs font-mono uppercase">
                      {report.format}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      report.enabled ? 'bg-indigo-500' : 'bg-gray-600'
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        report.enabled ? 'translate-x-6' : 'translate-x-1'
                      }`}
                    />
                  </button>
                  <button className="text-gray-400 hover:text-red-400 transition-colors">
                    <Trash2 className="h-5 w-5" />
                  </button>
                </div>
              </div>

              <div className="pt-3 border-t border-gray-700">
                <p className="text-xs text-gray-500 mb-2">Recipients:</p>
                <div className="flex flex-wrap gap-2">
                  {report.recipients.map((email, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 bg-gray-700/50 border border-gray-600 text-gray-300 rounded text-xs font-mono"
                    >
                      {email}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}

          <button className="w-full py-4 border-2 border-dashed border-gray-700 text-gray-400 rounded-lg hover:bg-gray-800 hover:text-gray-200 hover:border-gray-600 transition-colors flex items-center justify-center gap-2 font-medium">
            <Plus className="h-5 w-5" />
            Create New Scheduled Report
          </button>
        </div>

        <div className="sticky bottom-0 bg-gray-900 border-t border-gray-800 p-4">
          <p className="text-xs text-gray-500 text-center">
            Reports are generated and sent automatically based on your schedule. Recipients will receive a secure download link.
          </p>
        </div>
      </div>
    </div>
  );
}

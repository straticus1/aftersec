'use client';

import { useState } from 'react';
import { Filter, X, Save, Star, ChevronDown } from 'lucide-react';
import { FilterState, FilterPreset } from '@/lib/hooks/useFilters';

interface FilterOption {
  label: string;
  value: string;
}

interface FilterBarProps {
  filters: FilterState;
  onFilterChange: <K extends keyof FilterState>(key: K, value: FilterState[K]) => void;
  onClearFilters: () => void;
  savedPresets?: FilterPreset[];
  onApplyPreset?: (presetId: string) => void;
  onSavePreset?: (name: string) => void;
  hasActiveFilters: boolean;
  resultCount: number;
  totalCount: number;
  statusOptions?: FilterOption[];
  severityOptions?: FilterOption[];
  timeRangeOptions?: FilterOption[];
}

export default function FilterBar({
  filters,
  onFilterChange,
  onClearFilters,
  savedPresets = [],
  onApplyPreset,
  onSavePreset,
  hasActiveFilters,
  resultCount,
  totalCount,
  statusOptions = [
    { label: 'Passed', value: 'passed' },
    { label: 'Failed', value: 'failed' },
    { label: 'Warning', value: 'warning' },
  ],
  severityOptions = [
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' },
  ],
  timeRangeOptions = [
    { label: 'Last 15 minutes', value: '15m' },
    { label: 'Last hour', value: '1h' },
    { label: 'Last 24 hours', value: '24h' },
    { label: 'Last 7 days', value: '7d' },
    { label: 'Last 30 days', value: '30d' },
  ],
}: FilterBarProps) {
  const [showPresets, setShowPresets] = useState(false);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [presetName, setPresetName] = useState('');

  const toggleMultiSelect = (key: 'status' | 'severity', value: string) => {
    const current = (filters[key] || []) as string[];
    const updated = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onFilterChange(key, updated.length > 0 ? updated : undefined);
  };

  const handleSavePreset = () => {
    if (presetName.trim() && onSavePreset) {
      onSavePreset(presetName.trim());
      setPresetName('');
      setShowSaveDialog(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-6 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Filter className="h-5 w-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Filters</h3>
          {hasActiveFilters && (
            <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-full text-xs font-semibold">
              {resultCount} / {totalCount}
            </span>
          )}
        </div>
        <div className="flex gap-2">
          {savedPresets.length > 0 && (
            <div className="relative">
              <button
                onClick={() => setShowPresets(!showPresets)}
                className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 border border-gray-700 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
              >
                <Star className="h-4 w-4" />
                Presets
                <ChevronDown className={`h-4 w-4 transition-transform ${showPresets ? 'rotate-180' : ''}`} />
              </button>
              {showPresets && (
                <div className="absolute right-0 mt-2 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-2xl z-10 overflow-hidden">
                  {savedPresets.map((preset) => (
                    <button
                      key={preset.id}
                      onClick={() => {
                        onApplyPreset?.(preset.id);
                        setShowPresets(false);
                      }}
                      className="w-full text-left px-4 py-2.5 hover:bg-gray-700 transition-colors text-sm text-gray-300 border-b border-gray-700 last:border-0"
                    >
                      {preset.name}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
          {onSavePreset && hasActiveFilters && (
            <button
              onClick={() => setShowSaveDialog(true)}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 border border-gray-700 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
            >
              <Save className="h-4 w-4" />
              Save
            </button>
          )}
          {hasActiveFilters && (
            <button
              onClick={onClearFilters}
              className="flex items-center gap-2 px-3 py-1.5 bg-red-900/20 border border-red-500/30 hover:bg-red-900/30 rounded-lg text-sm text-red-400 transition-colors"
            >
              <X className="h-4 w-4" />
              Clear All
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Status Filter */}
        <div>
          <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Status
          </label>
          <div className="flex flex-wrap gap-2">
            {statusOptions.map((option) => (
              <button
                key={option.value}
                onClick={() => toggleMultiSelect('status', option.value)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  filters.status?.includes(option.value)
                    ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-900/20'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {/* Severity Filter */}
        <div>
          <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Severity
          </label>
          <div className="flex flex-wrap gap-2">
            {severityOptions.map((option) => (
              <button
                key={option.value}
                onClick={() => toggleMultiSelect('severity', option.value)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  filters.severity?.includes(option.value)
                    ? option.value === 'critical'
                      ? 'bg-red-500 text-white shadow-lg shadow-red-900/20'
                      : option.value === 'high'
                      ? 'bg-amber-500 text-white shadow-lg shadow-amber-900/20'
                      : 'bg-indigo-600 text-white shadow-lg shadow-indigo-900/20'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {/* Time Range Filter */}
        <div>
          <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Time Range
          </label>
          <select
            value={filters.timeRange || ''}
            onChange={(e) => onFilterChange('timeRange', e.target.value || undefined)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All time</option>
            {timeRangeOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Save Preset Dialog */}
      {showSaveDialog && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-lg font-semibold text-white mb-4">Save Filter Preset</h3>
            <input
              type="text"
              value={presetName}
              onChange={(e) => setPresetName(e.target.value)}
              placeholder="Enter preset name..."
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 mb-4"
              onKeyDown={(e) => e.key === 'Enter' && handleSavePreset()}
            />
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowSaveDialog(false)}
                className="px-4 py-2 bg-gray-800 border border-gray-700 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSavePreset}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm text-white font-semibold transition-colors shadow-lg shadow-indigo-500/20"
              >
                Save Preset
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

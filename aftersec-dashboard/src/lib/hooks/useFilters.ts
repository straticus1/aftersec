'use client';

import { useState, useMemo } from 'react';

export interface FilterPreset {
  id: string;
  name: string;
  filters: FilterState;
}

export interface FilterState {
  search?: string;
  status?: string[];
  severity?: string[];
  timeRange?: string;
  tags?: string[];
  customFilters?: Record<string, any>;
}

export interface UseFiltersOptions<T> {
  data: T[];
  filterFn: (item: T, filters: FilterState) => boolean;
  initialFilters?: FilterState;
}

export function useFilters<T>({ data, filterFn, initialFilters = {} }: UseFiltersOptions<T>) {
  const [filters, setFilters] = useState<FilterState>(initialFilters);
  const [savedPresets, setSavedPresets] = useState<FilterPreset[]>([
    {
      id: 'critical-only',
      name: 'Critical Issues',
      filters: { severity: ['critical'], status: ['failed'] },
    },
    {
      id: 'recent-warnings',
      name: 'Recent Warnings',
      filters: { severity: ['high', 'medium'], timeRange: '24h' },
    },
  ]);

  const filteredData = useMemo(() => {
    return data.filter((item) => filterFn(item, filters));
  }, [data, filters, filterFn]);

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({});
  };

  const applyPreset = (presetId: string) => {
    const preset = savedPresets.find((p) => p.id === presetId);
    if (preset) {
      setFilters(preset.filters);
    }
  };

  const savePreset = (name: string) => {
    const newPreset: FilterPreset = {
      id: `preset-${Date.now()}`,
      name,
      filters: { ...filters },
    };
    setSavedPresets((prev) => [...prev, newPreset]);
  };

  const deletePreset = (presetId: string) => {
    setSavedPresets((prev) => prev.filter((p) => p.id !== presetId));
  };

  const hasActiveFilters = useMemo(() => {
    return Object.keys(filters).some((key) => {
      const value = filters[key as keyof FilterState];
      if (Array.isArray(value)) return value.length > 0;
      if (typeof value === 'string') return value.length > 0;
      if (typeof value === 'object') return Object.keys(value || {}).length > 0;
      return false;
    });
  }, [filters]);

  return {
    filters,
    filteredData,
    updateFilter,
    clearFilters,
    savedPresets,
    applyPreset,
    savePreset,
    deletePreset,
    hasActiveFilters,
    resultCount: filteredData.length,
    totalCount: data.length,
  };
}

// Common filter functions
export const filterHelpers = {
  matchesSearch: (text: string, search?: string): boolean => {
    if (!search) return true;
    return text.toLowerCase().includes(search.toLowerCase());
  },

  matchesMultiSelect: (value: string, selected?: string[]): boolean => {
    if (!selected || selected.length === 0) return true;
    return selected.includes(value);
  },

  matchesTimeRange: (timestamp: string, range?: string): boolean => {
    if (!range) return true;
    const time = new Date(timestamp).getTime();
    const now = Date.now();

    switch (range) {
      case '15m':
        return now - time <= 15 * 60 * 1000;
      case '1h':
        return now - time <= 60 * 60 * 1000;
      case '24h':
        return now - time <= 24 * 60 * 60 * 1000;
      case '7d':
        return now - time <= 7 * 24 * 60 * 60 * 1000;
      case '30d':
        return now - time <= 30 * 24 * 60 * 60 * 1000;
      default:
        return true;
    }
  },
};

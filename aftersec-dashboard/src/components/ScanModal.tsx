"use client";

import React, { useState, useEffect } from 'react';
import { X, FolderOpen, HardDrive, Plus, Trash2 } from 'lucide-react';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScan: (paths: string[], scanType: 'file' | 'volume', profile: string) => void;
}

interface Volume {
  path: string;
  size?: number;
  available?: number;
  filesystem?: string;
  mountPoint: string;
}

export default function ScanModal({ isOpen, onClose, onScan }: ScanModalProps) {
  const [scanType, setScanType] = useState<'file' | 'volume'>('file');
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [customPath, setCustomPath] = useState('');
  const [profile, setProfile] = useState('standard');
  const [volumes, setVolumes] = useState<Volume[]>([]);
  const [loadingVolumes, setLoadingVolumes] = useState(false);

  useEffect(() => {
    if (isOpen && scanType === 'volume') {
      loadVolumes();
    }
  }, [isOpen, scanType]);

  const loadVolumes = async () => {
    setLoadingVolumes(true);
    try {
      // This would call the backend API to get available volumes
      // For now, we'll use common paths
      const commonVolumes: Volume[] = [
        { path: '/', mountPoint: '/', filesystem: 'apfs' },
        { path: '/Volumes', mountPoint: '/Volumes', filesystem: 'apfs' },
        { path: '/System/Volumes/Data', mountPoint: '/System/Volumes/Data', filesystem: 'apfs' },
      ];

      // Try to fetch from API
      try {
        const response = await fetch('/api/volumes');
        if (response.ok) {
          const data = await response.json();
          setVolumes(data.volumes || commonVolumes);
        } else {
          setVolumes(commonVolumes);
        }
      } catch {
        setVolumes(commonVolumes);
      }
    } finally {
      setLoadingVolumes(false);
    }
  };

  const addPath = (path: string) => {
    if (path && !selectedPaths.includes(path)) {
      setSelectedPaths([...selectedPaths, path]);
      setCustomPath('');
    }
  };

  const removePath = (path: string) => {
    setSelectedPaths(selectedPaths.filter(p => p !== path));
  };

  const handleScan = async () => {
    if (selectedPaths.length > 0) {
      // Call the scan initiation API
      try {
        const response = await fetch('/api/scans/initiate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            paths: selectedPaths,
            scanType,
            profile
          })
        });

        const data = await response.json();

        if (data.success) {
          onScan(selectedPaths, scanType, profile);
          setSelectedPaths([]);
          setCustomPath('');
          onClose();
        } else {
          alert(`Failed to initiate scan: ${data.error}`);
        }
      } catch (error) {
        alert(`Error initiating scan: ${error}`);
      }
    }
  };

  const commonPaths = [
    { path: '/Users', label: 'All Users', icon: '👥' },
    { path: '/Applications', label: 'Applications', icon: '📱' },
    { path: '/Library', label: 'System Library', icon: '📚' },
    { path: '/private/tmp', label: 'Temporary Files', icon: '🗑️' },
    { path: '/usr/local', label: 'Local Programs', icon: '⚙️' },
  ];

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <FolderOpen className="h-6 w-6 text-indigo-400" />
            Initiate Malware Scan
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Scan Type Selection */}
          <div>
            <label className="block text-sm font-semibold text-gray-200 mb-3">
              Scan Type
            </label>
            <div className="grid grid-cols-2 gap-4">
              <button
                onClick={() => setScanType('file')}
                className={`p-4 rounded-lg border-2 transition-all ${
                  scanType === 'file'
                    ? 'border-indigo-500 bg-indigo-900/20 shadow-lg'
                    : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                }`}
              >
                <FolderOpen className={`h-8 w-8 mx-auto mb-2 ${scanType === 'file' ? 'text-indigo-400' : 'text-gray-400'}`} />
                <p className="text-sm font-semibold text-gray-200">File/Directory Scan</p>
                <p className="text-xs text-gray-500 mt-1">Scan specific files and folders</p>
              </button>
              <button
                onClick={() => setScanType('volume')}
                className={`p-4 rounded-lg border-2 transition-all ${
                  scanType === 'volume'
                    ? 'border-indigo-500 bg-indigo-900/20 shadow-lg'
                    : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                }`}
              >
                <HardDrive className={`h-8 w-8 mx-auto mb-2 ${scanType === 'volume' ? 'text-indigo-400' : 'text-gray-400'}`} />
                <p className="text-sm font-semibold text-gray-200">Volume Scan</p>
                <p className="text-xs text-gray-500 mt-1">Scan entire disks/volumes</p>
              </button>
            </div>
          </div>

          {/* Volume Selection (for volume scan) */}
          {scanType === 'volume' && (
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-3">
                Select Volumes/Disks
              </label>
              {loadingVolumes ? (
                <div className="text-center py-8 text-gray-400">Loading volumes...</div>
              ) : (
                <div className="grid grid-cols-1 gap-2">
                  {volumes.map((volume) => (
                    <button
                      key={volume.path}
                      onClick={() => addPath(volume.path)}
                      disabled={selectedPaths.includes(volume.path)}
                      className={`p-4 rounded-lg border text-left transition-all ${
                        selectedPaths.includes(volume.path)
                          ? 'border-green-500 bg-green-900/20 cursor-not-allowed'
                          : 'border-gray-700 bg-gray-800/50 hover:border-indigo-500 hover:bg-gray-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <HardDrive className={`h-5 w-5 ${selectedPaths.includes(volume.path) ? 'text-green-400' : 'text-gray-400'}`} />
                        <div className="flex-1">
                          <p className="text-sm font-semibold text-gray-200 font-mono">{volume.path}</p>
                          {volume.filesystem && (
                            <p className="text-xs text-gray-500 mt-1">Filesystem: {volume.filesystem}</p>
                          )}
                        </div>
                        {selectedPaths.includes(volume.path) && (
                          <span className="px-2 py-0.5 bg-green-500 text-white text-xs rounded-full font-bold">SELECTED</span>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Common Paths (for file scan) */}
          {scanType === 'file' && (
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-3">
                Quick Select Common Paths
              </label>
              <div className="grid grid-cols-2 gap-2">
                {commonPaths.map((item) => (
                  <button
                    key={item.path}
                    onClick={() => addPath(item.path)}
                    disabled={selectedPaths.includes(item.path)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      selectedPaths.includes(item.path)
                        ? 'border-green-500 bg-green-900/20 cursor-not-allowed'
                        : 'border-gray-700 bg-gray-800/50 hover:border-indigo-500 hover:bg-gray-800'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{item.icon}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-gray-200 truncate">{item.label}</p>
                        <p className="text-xs text-gray-500 font-mono truncate">{item.path}</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Custom Path Input */}
          <div>
            <label className="block text-sm font-semibold text-gray-200 mb-3">
              Add Custom Path
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    addPath(customPath);
                  }
                }}
                placeholder="/path/to/scan"
                className="flex-1 bg-gray-950 text-gray-200 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
              />
              <button
                onClick={() => addPath(customPath)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Add
              </button>
            </div>
          </div>

          {/* Selected Paths */}
          {selectedPaths.length > 0 && (
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-3">
                Selected Paths ({selectedPaths.length})
              </label>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {selectedPaths.map((path) => (
                  <div
                    key={path}
                    className="flex items-center justify-between p-3 bg-gray-800/50 border border-gray-700 rounded-lg"
                  >
                    <span className="text-sm font-mono text-gray-200">{path}</span>
                    <button
                      onClick={() => removePath(path)}
                      className="text-red-400 hover:text-red-300 transition-colors"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan Profile */}
          <div>
            <label className="block text-sm font-semibold text-gray-200 mb-3">
              Scan Profile
            </label>
            <div className="grid grid-cols-3 gap-4">
              {['quick', 'standard', 'deep'].map((p) => (
                <button
                  key={p}
                  onClick={() => setProfile(p)}
                  className={`p-3 rounded-lg border-2 transition-all ${
                    profile === p
                      ? 'border-indigo-500 bg-indigo-900/20'
                      : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                  }`}
                >
                  <p className="text-sm font-semibold text-gray-200 capitalize">{p}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {p === 'quick' && 'Fast scan'}
                    {p === 'standard' && 'Balanced'}
                    {p === 'deep' && 'Thorough'}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-800">
          <button
            onClick={onClose}
            className="px-6 py-2 text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleScan}
            disabled={selectedPaths.length === 0}
            className={`px-6 py-2 rounded-lg font-semibold transition-all ${
              selectedPaths.length > 0
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'
                : 'bg-gray-700 text-gray-500 cursor-not-allowed'
            }`}
          >
            Start Scan ({selectedPaths.length} {selectedPaths.length === 1 ? 'path' : 'paths'})
          </button>
        </div>
      </div>
    </div>
  );
}

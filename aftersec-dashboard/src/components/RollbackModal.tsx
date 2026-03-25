"use client";

import React, { useState } from 'react';
import { History, X, GitCommit, CheckCircle2 } from 'lucide-react';

interface RollbackModalProps {
  isOpen: boolean;
  onClose: () => void;
  endpointName: string;
}

const mockCommits = [
  { id: 'c3f1a9b', date: '2 Hours Ago', message: 'Current State (Infected)', type: 'danger' },
  { id: '8a2b1c4', date: 'Yesterday, 14:20', message: 'User installed unknown pkg', type: 'warning' },
  { id: 'f00d8b2', date: '3 Days Ago', message: 'Baseline: Enforced STRICT SIP', type: 'baseline', active: true },
  { id: '1b2a3c4', date: 'Last Week', message: 'Initial Agent Provisioning', type: 'baseline' },
];

export default function RollbackModal({ isOpen, onClose, endpointName }: RollbackModalProps) {
  const [isRollingBack, setIsRollingBack] = useState(false);
  const [success, setSuccess] = useState(false);

  if (!isOpen) return null;

  const handleRollback = () => {
    setIsRollingBack(true);
    setTimeout(() => {
      setIsRollingBack(false);
      setSuccess(true);
      setTimeout(() => {
        onClose();
        setSuccess(false);
      }, 2000);
    }, 1500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-2xl shadow-2xl shadow-indigo-900/10 overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <History className="h-5 w-5 text-indigo-400" />
              Time-Travel Baseline Rollback
            </h2>
            <p className="text-xs text-gray-400 mt-1">Target: <span className="font-mono text-indigo-300">{endpointName}</span></p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 flex-1 overflow-y-auto bg-gray-950">
          {success ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <CheckCircle2 className="h-16 w-16 text-emerald-500 mb-4" />
              <h3 className="text-xl font-bold text-white">Rollback Successful</h3>
              <p className="text-gray-400 mt-2 text-sm">Target {endpointName} has been reverted to commit <code className="text-indigo-400">f00d8b2</code>.</p>
            </div>
          ) : (
            <>
              <p className="text-sm text-gray-300 mb-6 font-medium leading-relaxed">
                AfterSec maintains git-like commits of endpoint security configurations. Select a historical snapshot to instantly 
                revert the target's firewall, permissions, and service states to a known-good baseline.
              </p>

              <div className="space-y-4 relative before:absolute before:inset-0 before:left-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-800 before:to-transparent">
                {mockCommits.map((commit, i) => (
                  <div key={commit.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                    {/* Icon */}
                    <div className="flex items-center justify-center w-10 h-10 rounded-full border-4 border-gray-950 bg-gray-900 text-gray-500 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 z-10 transition-colors group-hover:bg-indigo-900/50 group-hover:border-indigo-500/30 group-hover:text-indigo-400">
                      <GitCommit className="w-4 h-4" />
                    </div>
                    {/* Card */}
                    <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-xl border border-gray-800 bg-gray-900/50 shadow-sm transition-all hover:bg-gray-800/80 cursor-pointer">
                      <div className="flex items-center justify-between space-x-2 mb-1">
                        <div className="font-bold text-white text-sm">{commit.date}</div>
                        <div className="font-mono text-xs text-indigo-400">{commit.id}</div>
                      </div>
                      <div className="text-xs text-gray-400 flex items-center justify-between mt-2">
                        {commit.message}
                        {commit.type === 'danger' && <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-500 font-bold ml-2">BAD</span>}
                        {commit.active && <span className="px-2 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 font-semibold ml-2">TARGET BASELINE</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {!success && (
          <div className="p-4 border-t border-gray-800 bg-gray-900 flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm font-semibold text-gray-400 hover:text-white transition-colors">Cancel</button>
            <button 
              onClick={handleRollback}
              disabled={isRollingBack}
              className={`px-5 py-2 text-sm font-bold rounded-lg transition-all flex items-center gap-2 shadow-lg shadow-indigo-900/20 ${
                isRollingBack ? 'bg-indigo-600/50 text-indigo-300 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-500 text-white'
              }`}
            >
              {isRollingBack ? (
                <>Rolling Back (Pushing payload)...</>
              ) : (
                <><History className="w-4 h-4" /> Execute Rollback to Baseline</>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

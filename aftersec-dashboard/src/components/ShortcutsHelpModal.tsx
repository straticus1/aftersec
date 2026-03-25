'use client';

import { X } from 'lucide-react';
import { useEffect } from 'react';

interface ShortcutItem {
  category: string;
  shortcuts: { keys: string[]; description: string }[];
}

const SHORTCUTS: ShortcutItem[] = [
  {
    category: 'Navigation',
    shortcuts: [
      { keys: ['⌘', 'D'], description: 'Go to Dashboard' },
      { keys: ['⌘', 'E'], description: 'Go to Endpoints' },
      { keys: ['⌘', 'X'], description: 'Go to Process X-Ray' },
      { keys: ['⌘', 'R'], description: 'Go to Detection Rules' },
      { keys: ['⌘', 'T'], description: 'Go to AI Triage' },
      { keys: ['⌘', 'C'], description: 'Go to Compliance' },
    ],
  },
  {
    category: 'Search & Filter',
    shortcuts: [
      { keys: ['⌘', 'K'], description: 'Focus search' },
      { keys: ['Esc'], description: 'Clear search / Close modal' },
    ],
  },
  {
    category: 'Actions',
    shortcuts: [
      { keys: ['⌘', 'Shift', 'I'], description: 'Isolate selected endpoint' },
      { keys: ['⌘', 'Shift', 'N'], description: 'Open notifications' },
      { keys: ['⌘', 'Shift', 'E'], description: 'Export current view' },
    ],
  },
  {
    category: 'General',
    shortcuts: [
      { keys: ['/'], description: 'Show this help dialog' },
    ],
  },
];

export default function ShortcutsHelpModal() {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('shortcuts-help-modal');
        if (modal && !modal.classList.contains('hidden')) {
          modal.classList.add('hidden');
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const closeModal = () => {
    const modal = document.getElementById('shortcuts-help-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  };

  return (
    <div
      id="shortcuts-help-modal"
      className="hidden fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4"
      onClick={closeModal}
    >
      <div
        className="bg-gray-900 border border-gray-800 rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-6 flex justify-between items-center">
          <h2 className="text-2xl font-bold text-white">Keyboard Shortcuts</h2>
          <button
            onClick={closeModal}
            className="text-gray-400 hover:text-white transition-colors"
            aria-label="Close"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="p-6 space-y-8">
          {SHORTCUTS.map((section) => (
            <div key={section.category}>
              <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider mb-4">
                {section.category}
              </h3>
              <div className="space-y-3">
                {section.shortcuts.map((shortcut, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg hover:bg-gray-800 transition-colors"
                  >
                    <span className="text-gray-300">{shortcut.description}</span>
                    <div className="flex gap-1">
                      {shortcut.keys.map((key, j) => (
                        <kbd
                          key={j}
                          className="px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-sm font-mono text-gray-300 shadow-md min-w-[2.5rem] text-center"
                        >
                          {key}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="sticky bottom-0 bg-gray-900 border-t border-gray-800 p-4">
          <p className="text-xs text-gray-500 text-center">
            Press <kbd className="px-2 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono">/</kbd> anytime to show this help
          </p>
        </div>
      </div>
    </div>
  );
}

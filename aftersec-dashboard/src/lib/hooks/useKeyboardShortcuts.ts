'use client';

import { useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';

export interface KeyboardShortcut {
  key: string;
  metaKey?: boolean;
  shiftKey?: boolean;
  ctrlKey?: boolean;
  altKey?: boolean;
  description: string;
  handler: () => void;
}

const SHORTCUTS_HELP_KEY = '?';

export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[], enabled: boolean = true) {
  const router = useRouter();

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!enabled) return;

      // Don't trigger shortcuts when typing in inputs
      const target = event.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        // Exception: Allow Escape to blur inputs
        if (event.key === 'Escape') {
          target.blur();
        }
        return;
      }

      for (const shortcut of shortcuts) {
        const metaMatch = shortcut.metaKey ? event.metaKey : !event.metaKey;
        const shiftMatch = shortcut.shiftKey ? event.shiftKey : !event.shiftKey;
        const ctrlMatch = shortcut.ctrlKey ? event.ctrlKey : !event.ctrlKey;
        const altMatch = shortcut.altKey ? event.altKey : !event.altKey;

        if (
          event.key.toLowerCase() === shortcut.key.toLowerCase() &&
          metaMatch &&
          shiftMatch &&
          ctrlMatch &&
          altMatch
        ) {
          event.preventDefault();
          shortcut.handler();
          return;
        }
      }
    },
    [shortcuts, enabled]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);
}

// Global shortcuts available across the entire app
export function useGlobalShortcuts() {
  const router = useRouter();

  const shortcuts: KeyboardShortcut[] = [
    {
      key: 'k',
      metaKey: true,
      description: 'Search endpoints',
      handler: () => {
        const searchInput = document.getElementById('global-search') as HTMLInputElement;
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      },
    },
    {
      key: 'd',
      metaKey: true,
      description: 'Go to Dashboard',
      handler: () => router.push('/'),
    },
    {
      key: 'e',
      metaKey: true,
      description: 'Go to Endpoints',
      handler: () => router.push('/endpoints'),
    },
    {
      key: 'x',
      metaKey: true,
      description: 'Go to Process X-Ray',
      handler: () => router.push('/xray'),
    },
    {
      key: 'r',
      metaKey: true,
      description: 'Go to Detection Rules',
      handler: () => router.push('/rules'),
    },
    {
      key: 't',
      metaKey: true,
      description: 'Go to AI Triage',
      handler: () => router.push('/triage'),
    },
    {
      key: 'c',
      metaKey: true,
      description: 'Go to Compliance',
      handler: () => router.push('/compliance'),
    },
    {
      key: 'n',
      metaKey: true,
      shiftKey: true,
      description: 'Toggle notifications',
      handler: () => {
        // Find and click the notification bell button
        const notificationButton = document.querySelector('[data-notification-toggle]') as HTMLButtonElement;
        if (notificationButton) {
          notificationButton.click();
        }
      },
    },
    {
      key: '/',
      description: 'Show keyboard shortcuts',
      handler: () => {
        const helpModal = document.getElementById('shortcuts-help-modal');
        if (helpModal) {
          helpModal.classList.remove('hidden');
        }
      },
    },
  ];

  useKeyboardShortcuts(shortcuts);
}

// Shortcut hint component
export function ShortcutHint({ keys }: { keys: string[] }) {
  return (
    <span className="ml-auto flex gap-1 text-xs text-gray-500 font-mono">
      {keys.map((key, i) => (
        <kbd
          key={i}
          className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400"
        >
          {key}
        </kbd>
      ))}
    </span>
  );
}

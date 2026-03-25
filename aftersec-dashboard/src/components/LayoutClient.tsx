'use client';

import { useGlobalShortcuts } from '@/lib/hooks/useKeyboardShortcuts';
import ShortcutsHelpModal from './ShortcutsHelpModal';
import Sidebar from './Sidebar';

export default function LayoutClient({ children }: { children: React.ReactNode }) {
  useGlobalShortcuts();

  return (
    <>
      <div className="flex h-screen w-full">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
      <ShortcutsHelpModal />
    </>
  );
}

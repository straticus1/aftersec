'use client';

import { signOut, useSession } from 'next-auth/react';
import Link from 'next/link';

export default function Header() {
  const { data: session } = useSession();

  return (
    <header className="border-b border-indigo-900/30 bg-slate-900/40 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-8 py-4 flex justify-between items-center">
        <div className="flex items-center gap-8">
          <Link href="/" className="text-2xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400 hover:from-indigo-300 hover:to-cyan-300 transition-all">
            AfterSec
          </Link>
          <nav className="flex gap-6">
            <Link href="/" className="text-sm font-medium text-slate-400 hover:text-cyan-400 transition-colors">
              Dashboard
            </Link>
            <Link href="/endpoints" className="text-sm font-medium text-slate-400 hover:text-cyan-400 transition-colors">
              Endpoints
            </Link>
            <Link href="/scans" className="text-sm font-medium text-slate-400 hover:text-cyan-400 transition-colors">
              Scans
            </Link>
          </nav>
        </div>

        {session?.user && (
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-slate-200">{session.user.name}</p>
              <p className="text-xs text-slate-500">{session.user.role}</p>
            </div>
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-all border border-slate-700"
            >
              Sign Out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

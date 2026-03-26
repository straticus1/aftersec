'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert,
  LayoutDashboard,
  Activity,
  Server,
  FileCheck,
  Settings,
  ChevronDown,
  CodeXml,
  Sparkles,
  Search,
  ShieldCheck,
  BrainCircuit,
  Bot
} from 'lucide-react';
import { useTenant } from '@/lib/contexts/TenantContext';
import { useAuthContext } from '@/lib/contexts/AuthContext';
import RoleGuard from './RoleGuard';
import { ShortcutHint } from '@/lib/hooks/useKeyboardShortcuts';
import NotificationCenter from './NotificationCenter';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, shortcut: ['⌘', 'D'] },
  { name: 'Endpoints', href: '/endpoints', icon: Server, shortcut: ['⌘', 'E'] },
  { name: 'Process X-Ray', href: '/xray', icon: Activity, shortcut: ['⌘', 'X'] },
  { name: 'Detection Rules', href: '/rules', icon: CodeXml, shortcut: ['⌘', 'R'] },
  { name: 'AI Triage', href: '/triage', icon: Sparkles, shortcut: ['⌘', 'T'] },
  { name: 'Endpoint AI', href: '/endpoint-ai', icon: BrainCircuit, shortcut: ['⌘', 'L'] },
  { name: 'Bandit AI', href: '/bandit', icon: Bot, shortcut: ['⌘', 'B'] },
  { name: 'Signatures', href: '/signatures', icon: ShieldCheck, shortcut: ['⌘', 'S'] },
  { name: 'Compliance', href: '/compliance', icon: FileCheck, shortcut: ['⌘', 'C'] },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { currentTenant, availableTenants, setCurrentTenant } = useTenant();
  const { role, setRole } = useAuthContext();

  // Hide sidebar on login page
  if (pathname === '/login') return null;

  return (
    <div className="flex h-full w-64 flex-col bg-gray-900 border-r border-gray-800 text-gray-300">
      <div className="flex h-16 shrink-0 items-center justify-between px-6 border-b border-gray-800 bg-gray-950">
        <div className="flex items-center">
          <ShieldAlert className="h-6 w-6 text-indigo-500 mr-3" />
          <span className="text-lg font-bold text-white tracking-widest">AFTERSEC</span>
        </div>
        <NotificationCenter />
      </div>

      <div className="px-4 py-4 border-b border-gray-800">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
          <input
            id="global-search"
            type="text"
            placeholder="Search endpoints... (⌘K)"
            className="w-full pl-10 pr-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
      </div>

      <div className="px-4 py-4 border-b border-gray-800">
        <div className="mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          Current Tenant
        </div>
        <div className="relative">
          <select
            className="w-full appearance-none rounded-md bg-gray-800 py-2 pl-3 pr-10 text-sm font-medium text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            value={currentTenant?.id || ''}
            onChange={(e) => {
              const tenant = availableTenants.find(t => t.id === e.target.value);
              if (tenant) setCurrentTenant(tenant);
            }}
          >
            {availableTenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
            <ChevronDown className="h-4 w-4 text-gray-400" />
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-4 py-4 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`group flex items-center justify-between rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-indigo-600/10 text-indigo-400'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <div className="flex items-center">
                <item.icon
                  className={`mr-3 h-5 w-5 flex-shrink-0 ${
                    isActive ? 'text-indigo-400' : 'text-gray-500 group-hover:text-gray-300'
                  }`}
                />
                {item.name}
              </div>
              {item.shortcut && <ShortcutHint keys={item.shortcut} />}
            </Link>
          );
        })}

        <RoleGuard allowedRoles={['admin']}>
          <div className="pt-4 mt-4 border-t border-gray-800">
            <Link
              href="/settings"
              className={`group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                pathname === '/settings'
                  ? 'bg-indigo-600/10 text-indigo-400' 
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Settings 
                className={`mr-3 h-5 w-5 flex-shrink-0 ${
                  pathname === '/settings' ? 'text-indigo-400' : 'text-gray-500 group-hover:text-gray-300'
                }`} 
              />
              Settings
            </Link>
          </div>
        </RoleGuard>
      </nav>

      <div className="border-t border-gray-800 p-4">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <div className="h-8 w-8 rounded-full bg-indigo-900 flex items-center justify-center text-indigo-300 font-bold">
              {role.charAt(0).toUpperCase()}
            </div>
          </div>
          <div className="ml-3">
            <p className="text-sm font-medium text-white">Current User</p>
            <div className="flex items-center">
              <span className="text-xs text-gray-400 mr-2">Role:</span>
              <select 
                className="text-xs bg-gray-800 text-indigo-400 border-none rounded focus:ring-0 py-0.5 px-1"
                value={role}
                onChange={(e) => setRole(e.target.value as any)}
              >
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

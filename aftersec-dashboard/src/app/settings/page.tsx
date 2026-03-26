"use client";

import React from 'react';
import RoleGuard from '@/components/RoleGuard';
import { useAuthContext } from '@/lib/contexts/AuthContext';
import { useTenant } from '@/lib/contexts/TenantContext';
import { useSettings } from '@/lib/contexts/SettingsContext';
import { useTheme } from '@/lib/contexts/ThemeContext';
import { Palette, Calendar } from 'lucide-react';
import ScheduledReportsModal from '@/components/ScheduledReportsModal';

export default function SettingsPage() {
  const { role } = useAuthContext();
  const { availableTenants } = useTenant();
  const { useMockData, setUseMockData } = useSettings();
  const { theme, setTheme } = useTheme();
  const [showScheduledReports, setShowScheduledReports] = React.useState(false);

  return (
    <div className="min-h-screen relative p-8">
      <header className="mb-10">
        <h1 className="text-3xl font-extrabold tracking-tight text-white pb-1">
          Organization Settings
        </h1>
        <p className="text-gray-400 mt-1 text-sm font-medium">
          Manage roles, access, and tenant configurations.
        </p>
      </header>

      <RoleGuard 
        allowedRoles={['admin']} 
        fallback={
          <div className="bg-red-900/20 border border-red-500/30 text-red-400 p-6 rounded-xl flex items-center justify-center">
            <p className="font-semibold text-lg">ACCESS DENIED: Administrator privileges required.</p>
          </div>
        }
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* User & Role Management */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl">
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3">User Management (RBAC)</h2>
            <div className="space-y-4">
              {[1, 2, 3].map((user) => (
                <div key={user} className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
                   <div>
                     <p className="text-sm font-semibold text-gray-200">user{user}@example.com</p>
                     <p className="text-xs text-gray-500 mt-1">Last active: 2 hours ago</p>
                   </div>
                   <select className="bg-gray-950 text-indigo-400 border border-gray-700 rounded-md py-1.5 px-3 text-sm focus:ring-0">
                     <option value="admin">Admin</option>
                     <option value="analyst">Analyst</option>
                     <option value="viewer">Viewer</option>
                   </select>
                </div>
              ))}
              <button className="w-full mt-4 py-2 border border-dashed border-gray-700 text-gray-400 rounded-lg hover:bg-gray-800 hover:text-gray-200 transition-colors text-sm font-medium">
                 + Invite New User
              </button>
            </div>
          </section>

          {/* Tenant Management */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl">
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3">Tenants Management</h2>
            <div className="space-y-4">
              {availableTenants.map((tenant) => (
                <div key={tenant.id} className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
                   <div>
                     <p className="text-sm font-semibold text-gray-200">{tenant.name}</p>
                     <p className="text-xs font-mono text-indigo-400 mt-1">{tenant.id}</p>
                   </div>
                   <button className="text-gray-400 hover:text-white text-xs font-semibold px-3 py-1.5 bg-gray-700 rounded transition-colors">
                     Manage
                   </button>
                </div>
              ))}
              <button className="w-full mt-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors text-sm font-semibold shadow-lg shadow-indigo-500/20">
                 Create New Tenant
              </button>
            </div>
          </section>

          {/* Data Settings */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl lg:col-span-2">
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3">Data & Telemetry Settings</h2>
            <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
               <div>
                 <p className="text-sm font-semibold text-gray-200">Enable Mock Data</p>
                 <p className="text-xs text-gray-500 mt-1">When enabled, the dashboard simulates real-time scan telemetry and uses mock charts. Disable this when connecting to production API endpoints.</p>
               </div>
               <button
                 onClick={() => setUseMockData(!useMockData)}
                 className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-gray-900 ${
                   useMockData ? 'bg-indigo-500' : 'bg-gray-600'
                 }`}
               >
                 <span
                   className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                     useMockData ? 'translate-x-6' : 'translate-x-1'
                   }`}
                 />
               </button>
            </div>
          </section>

          {/* Accessibility & Theme Settings */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl lg:col-span-2">
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3 flex items-center gap-2">
              <Palette className="h-5 w-5 text-indigo-400" />
              Accessibility & Display Settings
            </h2>
            <div>
              <div className="mb-4">
                <p className="text-sm font-semibold text-gray-200 mb-2">Dark Theme Variant</p>
                <p className="text-xs text-gray-500 mb-4">Choose a high-contrast dark theme optimized for accessibility. All themes maintain maximum contrast for readability.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <button
                  onClick={() => setTheme('dark')}
                  className={`p-4 rounded-lg border-2 transition-all ${
                    theme === 'dark'
                      ? 'border-indigo-500 bg-indigo-900/20 shadow-lg shadow-indigo-900/20'
                      : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-semibold text-gray-200">Dark (Default)</span>
                    {theme === 'dark' && (
                      <span className="px-2 py-0.5 bg-indigo-500 text-white text-xs rounded-full font-bold">ACTIVE</span>
                    )}
                  </div>
                  <div className="h-16 bg-gradient-to-br from-gray-950 via-gray-900 to-gray-800 rounded border border-gray-800 flex items-center justify-center">
                    <span className="text-xs font-mono text-gray-400">High Contrast</span>
                  </div>
                </button>

                <button
                  onClick={() => setTheme('dark-blue')}
                  className={`p-4 rounded-lg border-2 transition-all ${
                    theme === 'dark-blue'
                      ? 'border-indigo-500 bg-indigo-900/20 shadow-lg shadow-indigo-900/20'
                      : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-semibold text-gray-200">Dark Blue</span>
                    {theme === 'dark-blue' && (
                      <span className="px-2 py-0.5 bg-indigo-500 text-white text-xs rounded-full font-bold">ACTIVE</span>
                    )}
                  </div>
                  <div className="h-16 bg-gradient-to-br from-[#0a0e13] via-[#1a1f2e] to-[#252b3b] rounded border border-[#2f3747] flex items-center justify-center">
                    <span className="text-xs font-mono text-blue-300">Blue Tint</span>
                  </div>
                </button>

                <button
                  onClick={() => setTheme('pure-black')}
                  className={`p-4 rounded-lg border-2 transition-all ${
                    theme === 'pure-black'
                      ? 'border-indigo-500 bg-indigo-900/20 shadow-lg shadow-indigo-900/20'
                      : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-semibold text-gray-200">Pure Black</span>
                    {theme === 'pure-black' && (
                      <span className="px-2 py-0.5 bg-indigo-500 text-white text-xs rounded-full font-bold">ACTIVE</span>
                    )}
                  </div>
                  <div className="h-16 bg-gradient-to-br from-black via-[#0d0d0d] to-[#1a1a1a] rounded border border-[#262626] flex items-center justify-center">
                    <span className="text-xs font-mono text-white">OLED / Max Contrast</span>
                  </div>
                </button>
              </div>
            </div>
          </section>

          {/* macOS Kernel Parameters (sysctl) */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl lg:col-span-2 relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
              <svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2v20"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
            </div>
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3">macOS Kernel Parameters (sysctl)</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 relative z-10">
              
              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start mb-2">
                    <p className="text-sm font-bold text-gray-200 font-mono">net.inet.tcp.blackhole</p>
                    <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold">Network</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">Drops TCP segments to closed ports without returning a RST, preventing port scanning reconnaissance.</p>
                </div>
                <select className="bg-gray-950 text-indigo-400 border border-gray-700 rounded-md py-1.5 px-3 text-sm focus:ring-0 w-full font-mono">
                  <option value="2">2 (Drop all)</option>
                  <option value="1">1 (Drop SYN only)</option>
                  <option value="0">0 (Disabled)</option>
                </select>
              </div>

              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start mb-2">
                    <p className="text-sm font-bold text-gray-200 font-mono">net.inet.udp.blackhole</p>
                    <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold">Network</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">Drops UDP datagrams to closed ports silently without returning an ICMP Port Unreachable packet.</p>
                </div>
                <div className="flex items-center justify-between bg-gray-950 px-3 py-1.5 rounded-md border border-gray-700 text-sm">
                  <span className="text-gray-400">Enabled</span>
                  <div className="relative inline-flex h-5 w-9 items-center rounded-full bg-indigo-500">
                    <span className="inline-block h-3 w-3 transform rounded-full bg-white translate-x-5" />
                  </div>
                </div>
              </div>

              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start mb-2">
                    <p className="text-sm font-bold text-gray-200 font-mono">kern.securelevel</p>
                    <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded text-xs font-semibold">System</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">System immutability level. Level 1 prevents altering immutable flags and denies raw disk writing.</p>
                </div>
                <select className="bg-gray-950 text-amber-400 border border-gray-700 rounded-md py-1.5 px-3 text-sm focus:ring-0 w-full font-mono">
                  <option value="1">1 (Highly Secure)</option>
                  <option value="0">0 (Default)</option>
                  <option value="-1">-1 (Permanently Insecure)</option>
                </select>
              </div>

              <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50 flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-start mb-2">
                    <p className="text-sm font-bold text-gray-200 font-mono">security.mac.vnode_enforce</p>
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-semibold">Mandatory Access</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">Enforces Mandatory Access Control (MAC) policies on file system vnodes.</p>
                </div>
                <div className="flex items-center justify-between bg-gray-950 px-3 py-1.5 rounded-md border border-gray-700 text-sm">
                  <span className="text-gray-400">Enabled</span>
                  <div className="relative inline-flex h-5 w-9 items-center rounded-full bg-indigo-500">
                    <span className="inline-block h-3 w-3 transform rounded-full bg-white translate-x-5" />
                  </div>
                </div>
              </div>

            </div>
          </section>

          {/* Scheduled Reports */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl lg:col-span-2">
            <h2 className="text-lg font-semibold text-white mb-6 border-b border-gray-800 pb-3 flex items-center gap-2">
              <Calendar className="h-5 w-5 text-indigo-400" />
              Automated Reporting
            </h2>
            <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
               <div>
                 <p className="text-sm font-semibold text-gray-200">Scheduled Reports</p>
                 <p className="text-xs text-gray-500 mt-1">Configure automated security reports delivered via email on a recurring schedule (daily, weekly, monthly).</p>
               </div>
               <button
                 onClick={() => setShowScheduledReports(true)}
                 className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors text-sm font-semibold shadow-lg shadow-indigo-500/20"
               >
                 Manage Reports
               </button>
            </div>
          </section>
        </div>
      </RoleGuard>

      {/* Global Save Action Bar */}
      <div className="fixed bottom-0 left-0 right-0 bg-gray-900/95 backdrop-blur-sm border-t border-gray-800 p-4 shadow-[0_-10px_30px_rgba(0,0,0,0.5)] z-50 transform transition-transform ml-64 flex justify-end gap-4">
        <button 
          onClick={() => alert("Settings configuration saved and propagated to endpoints.")} 
          className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-2.5 rounded-lg font-bold shadow-lg shadow-indigo-500/20 transition-all"
        >
          Save Configuration
        </button>
      </div>

      <ScheduledReportsModal
        isOpen={showScheduledReports}
        onClose={() => setShowScheduledReports(false)}
      />
    </div>
  );
}

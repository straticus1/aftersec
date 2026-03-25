'use client';

import { SessionProvider } from 'next-auth/react';
import { ReactNode } from 'react';
import { AuthProvider } from '@/lib/contexts/AuthContext';
import { TenantProvider } from '@/lib/contexts/TenantContext';
import { SettingsProvider } from '@/lib/contexts/SettingsContext';
import { ThemeProvider } from '@/lib/contexts/ThemeContext';
import { NotificationProvider } from '@/lib/contexts/NotificationContext';

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <ThemeProvider>
        <NotificationProvider>
          <SettingsProvider>
            <AuthProvider>
              <TenantProvider>
                {children}
              </TenantProvider>
            </AuthProvider>
          </SettingsProvider>
        </NotificationProvider>
      </ThemeProvider>
    </SessionProvider>
  );
}

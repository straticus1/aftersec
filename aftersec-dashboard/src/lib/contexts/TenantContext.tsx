'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';

export interface Tenant {
  id: string;
  name: string;
}

interface TenantContextType {
  currentTenant: Tenant | null;
  setCurrentTenant: (tenant: Tenant) => void;
  availableTenants: Tenant[];
}

const mockTenants: Tenant[] = [
  { id: 'tenant-1', name: 'Acme Corp' },
  { id: 'tenant-2', name: 'Stark Industries' },
  { id: 'tenant-3', name: 'Wayne Enterprises' },
];

const TenantContext = createContext<TenantContextType | undefined>(undefined);

export function TenantProvider({ children }: { children: ReactNode }) {
  const [currentTenant, setCurrentTenant] = useState<Tenant | null>(mockTenants[0]);

  return (
    <TenantContext.Provider
      value={{
        currentTenant,
        setCurrentTenant,
        availableTenants: mockTenants,
      }}
    >
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const context = useContext(TenantContext);
  if (context === undefined) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
}

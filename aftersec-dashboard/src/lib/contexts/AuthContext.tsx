'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';

export type UserRole = 'admin' | 'analyst' | 'viewer';

interface AuthContextType {
  role: UserRole;
  setRole: (role: UserRole) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  // Defaulting to admin to allow viewing all features initially
  const [role, setRole] = useState<UserRole>('admin');

  return (
    <AuthContext.Provider value={{ role, setRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuthContext() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}

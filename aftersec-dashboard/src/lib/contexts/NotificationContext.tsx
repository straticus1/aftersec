'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export interface Notification {
  id: string;
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  timestamp: string;
  read: boolean;
  acknowledged: boolean;
  snoozedUntil?: string;
  endpoint?: string;
  alertId?: string;
}

interface NotificationContextType {
  notifications: Notification[];
  unreadCount: number;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  acknowledge: (id: string) => void;
  snooze: (id: string, duration: number) => void;
  dismiss: (id: string) => void;
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read' | 'acknowledged'>) => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

const mockNotifications: Notification[] = [
  {
    id: 'notif-1',
    title: 'Critical: Suspicious Process Detected',
    message: 'Endpoint mac-studio-dev detected curl piped to python3 accessing keychain',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    read: false,
    acknowledged: false,
    endpoint: 'mac-studio-dev',
    alertId: 'ALT-9921',
  },
  {
    id: 'notif-2',
    title: 'High: Network Beaconing Detected',
    message: 'Unusual network beaconing pattern to Russian IP detected on prod-api-02',
    severity: 'high',
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    read: false,
    acknowledged: false,
    endpoint: 'prod-api-02',
    alertId: 'ALT-9920',
  },
  {
    id: 'notif-3',
    title: 'Medium: Failed SSH Attempts',
    message: 'Multiple failed SSH authentication attempts on db-replica-01',
    severity: 'medium',
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    read: true,
    acknowledged: false,
    endpoint: 'db-replica-01',
    alertId: 'ALT-9919',
  },
  {
    id: 'notif-4',
    title: 'Info: System Update Available',
    message: 'AfterSec agent v2.1.0 is available with new detection rules',
    severity: 'info',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    read: true,
    acknowledged: true,
  },
];

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>(mockNotifications);

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAsRead = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const markAllAsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const acknowledge = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, acknowledged: true, read: true } : n))
    );
  };

  const snooze = (id: string, durationMinutes: number) => {
    const snoozedUntil = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, snoozedUntil, read: true } : n))
    );

    // Auto-unsnooze after duration
    setTimeout(() => {
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, snoozedUntil: undefined, read: false } : n))
      );
    }, durationMinutes * 60 * 1000);
  };

  const dismiss = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  const addNotification = (notification: Omit<Notification, 'id' | 'timestamp' | 'read' | 'acknowledged'>) => {
    const newNotification: Notification = {
      ...notification,
      id: `notif-${Date.now()}`,
      timestamp: new Date().toISOString(),
      read: false,
      acknowledged: false,
    };
    setNotifications((prev) => [newNotification, ...prev]);
  };

  // Filter out snoozed notifications from display
  const visibleNotifications = notifications.filter((n) => {
    if (!n.snoozedUntil) return true;
    return new Date(n.snoozedUntil) < new Date();
  });

  return (
    <NotificationContext.Provider
      value={{
        notifications: visibleNotifications,
        unreadCount,
        markAsRead,
        markAllAsRead,
        acknowledge,
        snooze,
        dismiss,
        addNotification,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  return context;
}

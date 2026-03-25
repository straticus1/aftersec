'use client';

import { useState, useRef, useEffect } from 'react';
import { Bell, Check, Clock, X, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import { useNotifications } from '@/lib/contexts/NotificationContext';
import { formatDistanceToNow } from 'date-fns';

export default function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    acknowledge,
    snooze,
    dismiss,
  } = useNotifications();

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="h-5 w-5" />;
      case 'medium':
        return <AlertCircle className="h-5 w-5" />;
      default:
        return <Info className="h-5 w-5" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'medium':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        data-notification-toggle
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 transition-colors"
      >
        <Bell className="h-5 w-5 text-gray-300" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center shadow-lg shadow-red-900/50">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-96 bg-gray-900 border border-gray-800 rounded-xl shadow-2xl z-50 max-h-[600px] flex flex-col">
          {/* Header */}
          <div className="p-4 border-b border-gray-800 flex justify-between items-center shrink-0">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Bell className="h-5 w-5 text-indigo-400" />
              Notifications
            </h3>
            {unreadCount > 0 && (
              <button
                onClick={markAllAsRead}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold"
              >
                Mark all read
              </button>
            )}
          </div>

          {/* Notifications List */}
          <div className="overflow-y-auto flex-1">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <Bell className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p className="text-sm">No notifications</p>
              </div>
            ) : (
              <div>
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-4 border-b border-gray-800 hover:bg-gray-800/50 transition-colors ${
                      !notification.read ? 'bg-indigo-900/10' : ''
                    }`}
                    onClick={() => !notification.read && markAsRead(notification.id)}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg border ${getSeverityColor(notification.severity)}`}>
                        {getSeverityIcon(notification.severity)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="text-sm font-semibold text-white line-clamp-1">
                            {notification.title}
                          </h4>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              dismiss(notification.id);
                            }}
                            className="text-gray-500 hover:text-gray-300 shrink-0"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </div>
                        <p className="text-xs text-gray-400 mt-1 line-clamp-2">
                          {notification.message}
                        </p>
                        {notification.endpoint && (
                          <p className="text-xs text-gray-500 font-mono mt-1">
                            {notification.endpoint}
                          </p>
                        )}
                        <div className="flex items-center gap-2 mt-2 text-xs text-gray-500">
                          <span>
                            {formatDistanceToNow(new Date(notification.timestamp), { addSuffix: true })}
                          </span>
                          {!notification.read && (
                            <span className="h-2 w-2 bg-indigo-500 rounded-full"></span>
                          )}
                        </div>

                        {/* Action Buttons */}
                        {!notification.acknowledged && notification.severity !== 'info' && (
                          <div className="flex gap-2 mt-3">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                acknowledge(notification.id);
                              }}
                              className="flex items-center gap-1 px-2 py-1 bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 text-green-400 rounded text-xs font-semibold transition-colors"
                            >
                              <Check className="h-3 w-3" />
                              Acknowledge
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                snooze(notification.id, 60);
                              }}
                              className="flex items-center gap-1 px-2 py-1 bg-gray-700/50 hover:bg-gray-700 border border-gray-600 text-gray-300 rounded text-xs font-semibold transition-colors"
                            >
                              <Clock className="h-3 w-3" />
                              Snooze 1h
                            </button>
                          </div>
                        )}

                        {notification.acknowledged && (
                          <div className="mt-2">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-500/10 border border-green-500/30 text-green-400 rounded-full text-xs font-semibold">
                              <Check className="h-3 w-3" />
                              Acknowledged
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          {notifications.length > 0 && (
            <div className="p-3 border-t border-gray-800 shrink-0">
              <p className="text-xs text-gray-500 text-center">
                <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono">
                  ⌘
                </kbd>
                <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono ml-1">
                  Shift
                </kbd>
                <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 rounded text-gray-400 font-mono ml-1">
                  N
                </kbd>
                <span className="ml-2">to toggle notifications</span>
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

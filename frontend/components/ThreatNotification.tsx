"use client";

import React from 'react';
import { useThreatDetection } from '@/contexts/ThreatDetectionContext';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface ThreatNotificationProps {
  className?: string;
}

export const ThreatNotification: React.FC<ThreatNotificationProps> = ({ className = "" }) => {
  const { recentThreatCount, isConnected, connectionStatus, markThreatsAsRead } = useThreatDetection();

  if (!isConnected && recentThreatCount === 0) {
    return null;
  }

  return (
    <div className={`fixed top-4 right-4 z-50 max-w-sm ${className}`}>
      {/* Connection Status */}
      {!isConnected && (
        <Card className="mb-2 border-yellow-200 bg-yellow-50 dark:bg-yellow-900/20 dark:border-yellow-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
              <p className="text-sm text-yellow-800 dark:text-yellow-200 font-medium">
                {connectionStatus}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Threat Notification */}
      {recentThreatCount > 0 && (
        <Card className="border-red-200 bg-red-50 dark:bg-red-900/20 dark:border-red-800 animate-pulse">
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-ping" />
                <p className="text-sm text-red-800 dark:text-red-200 font-medium">
                  {recentThreatCount} new threat{recentThreatCount > 1 ? 's' : ''} detected!
                </p>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={markThreatsAsRead}
                className="h-6 px-2 text-red-600 hover:text-red-800 hover:bg-red-100 dark:text-red-400 dark:hover:text-red-200 dark:hover:bg-red-900/40"
              >
                ✕
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

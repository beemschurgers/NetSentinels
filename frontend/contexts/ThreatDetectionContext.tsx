"use client";

import React, { createContext, useContext, useEffect, useRef, useState, ReactNode } from 'react';

interface ThreatEvent {
  timestamp: string;
  flow_key?: string;
  endpoints?: Array<{
    ip: string;
    port: number;
  }>;
  packet_count?: number;
  total_bytes?: number;
  is_threat: boolean;
  threat_type?: string;
  session_stats?: {
    total_flows: number;
    threat_flows: number;
    benign_flows: number;
  };
  status?: string;
  error?: string;
}

interface ThreatDetectionContextType {
  threats: ThreatEvent[];
  allFlows: ThreatEvent[];
  stats: {
    total_flows: number;
    threat_flows: number;
    benign_flows: number;
  };
  isConnected: boolean;
  connectionStatus: string;
  recentThreatCount: number;
  connectWebSocket: () => void;
  disconnectWebSocket: () => void;
  clearLog: () => void;
  markThreatsAsRead: () => void;
}

const ThreatDetectionContext = createContext<ThreatDetectionContextType | undefined>(undefined);

export const useThreatDetection = () => {
  const context = useContext(ThreatDetectionContext);
  if (context === undefined) {
    throw new Error('useThreatDetection must be used within a ThreatDetectionProvider');
  }
  return context;
};

interface ThreatDetectionProviderProps {
  children: ReactNode;
}

export const ThreatDetectionProvider: React.FC<ThreatDetectionProviderProps> = ({ children }) => {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [allFlows, setAllFlows] = useState<ThreatEvent[]>([]);
  const [stats, setStats] = useState({
    total_flows: 0,
    threat_flows: 0,
    benign_flows: 0,
  });
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("Initializing...");
  const [recentThreatCount, setRecentThreatCount] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const lastReadTimestampRef = useRef<number>(Date.now());

  const connectWebSocket = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    // Clear any existing reconnect timeout
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }

    try {
      const ws = new WebSocket("ws://localhost:8000/ws/threat-detection");
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setConnectionStatus("Connected - Threat detection active");
        console.log("Threat detection WebSocket connected");
      };

      ws.onmessage = (event) => {
        try {
          const data: ThreatEvent = JSON.parse(event.data);

          if (data.error) {
            setConnectionStatus(`Error: ${data.error}`);
            return;
          }

          if (data.status) {
            setConnectionStatus(data.status);
            if (data.session_stats) {
              setStats(data.session_stats);
            }
            return;
          }

          // Handle flow data
          if (data.timestamp) {
            const currentTime = Date.now();
            
            // Add to all flows
            setAllFlows((prev) => [data, ...prev.slice(0, 199)]); // Keep last 200

            // Add to threats if it's a threat
            if (data.is_threat) {
              setThreats((prev) => {
                const newThreats = [data, ...prev.slice(0, 99)]; // Keep last 100 threats
                
                // Update recent threat count if this is a new threat since last read
                if (currentTime > lastReadTimestampRef.current) {
                  setRecentThreatCount(prevCount => prevCount + 1);
                }
                
                return newThreats;
              });
            }

            // Update stats if available
            if (data.session_stats) {
              setStats(data.session_stats);
            }
          }
        } catch (err) {
          console.error("Error parsing threat data:", err);
        }
      };

      ws.onclose = (event) => {
        setIsConnected(false);
        wsRef.current = null;
        
        if (event.wasClean) {
          setConnectionStatus("Disconnected");
        } else {
          setConnectionStatus("Connection lost - Attempting to reconnect...");
          // Auto-reconnect after 3 seconds
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log("Attempting to reconnect threat detection...");
            connectWebSocket();
          }, 3000);
        }
      };

      ws.onerror = (error) => {
        setConnectionStatus("Connection error - Will retry");
        console.error("Threat detection WebSocket error:", error);
      };

    } catch (error) {
      console.error("Failed to create WebSocket connection:", error);
      setConnectionStatus("Failed to connect - Will retry");
      
      // Retry connection after 5 seconds
      reconnectTimeoutRef.current = setTimeout(() => {
        connectWebSocket();
      }, 5000);
    }
  };

  const disconnectWebSocket = () => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    setIsConnected(false);
    setConnectionStatus("Manually disconnected");
  };

  const clearLog = () => {
    setThreats([]);
    setAllFlows([]);
    setRecentThreatCount(0);
    lastReadTimestampRef.current = Date.now();
  };

  const markThreatsAsRead = () => {
    setRecentThreatCount(0);
    lastReadTimestampRef.current = Date.now();
  };

  // Auto-start connection when provider mounts
  useEffect(() => {
    connectWebSocket();
    
    // Cleanup on unmount
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const contextValue: ThreatDetectionContextType = {
    threats,
    allFlows,
    stats,
    isConnected,
    connectionStatus,
    recentThreatCount,
    connectWebSocket,
    disconnectWebSocket,
    clearLog,
    markThreatsAsRead,
  };

  return (
    <ThreatDetectionContext.Provider value={contextValue}>
      {children}
    </ThreatDetectionContext.Provider>
  );
};

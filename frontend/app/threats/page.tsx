"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useThreatDetection } from "@/contexts/ThreatDetectionContext";

export default function ThreatsPage() {
  const {
    threats,
    allFlows,
    stats,
    isConnected,
    connectionStatus,
    connectWebSocket,
    disconnectWebSocket,
    clearLog,
    markThreatsAsRead
  } = useThreatDetection();

  // Mark threats as read when visiting this page
  useEffect(() => {
    markThreatsAsRead();
  }, [markThreatsAsRead]);

  const formatFlowInfo = (flow: any) => {
    if (flow.endpoints && flow.endpoints.length === 2) {
      return `${flow.endpoints[0].ip}:${flow.endpoints[0].port} ↔ ${flow.endpoints[1].ip}:${flow.endpoints[1].port}`;
    }
    if (flow.flow_key) {
      return flow.flow_key;
    }
    return "N/A";
  };

  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold text-green-500 mb-4">Network Threat Detection</h1>
      
      {/* Controls */}
      <div className="mb-6 flex gap-4">
        <Button 
          onClick={connectWebSocket} 
          disabled={isConnected}
          className="bg-blue-600 hover:bg-blue-700"
        >
          Start Threat Detection
        </Button>
        <Button 
          onClick={disconnectWebSocket} 
          disabled={!isConnected}
          variant="destructive"
        >
          Stop Detection
        </Button>
        <Button onClick={clearLog} variant="outline">
          Clear Log
        </Button>
      </div>

      {/* Connection Status */}
      <div className={`flex items-center gap-4 p-4 rounded-lg shadow-md mb-6 ${
        isConnected 
          ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800' 
          : 'bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800'
      }`}>
        <div className="relative">
          <div className={`w-3 h-3 rounded-full ${
            isConnected ? 'bg-green-500' : 'bg-red-500'
          }`} />
          {isConnected && (
            <div className="w-3 h-3 bg-green-400 rounded-full animate-ping absolute top-0 left-0" />
          )}
        </div>
        <div>
          <p className={`font-semibold ${
            isConnected ? 'text-green-800 dark:text-green-200' : 'text-red-800 dark:text-red-200'
          }`}>
            {connectionStatus}
          </p>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Flows</p>
            <p className="text-2xl font-bold text-blue-600">{stats.total_flows}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Threat Flows</p>
            <p className="text-2xl font-bold text-red-500">{stats.threat_flows}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Benign Flows</p>
            <p className="text-2xl font-bold text-green-600">{stats.benign_flows}</p>
          </CardContent>
        </Card>
      </div>

      {/* Real-time Flow Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Flows */}
        <Card>
          <CardHeader>
            <CardTitle className="text-red-600">⚠️ Threat Flows</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px] w-full">
              <div className="space-y-2">
                {threats.length === 0 ? (
                  <p className="text-gray-500 text-center py-8">No threats detected</p>
                ) : (
                  threats.map((threat, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-sm font-semibold text-red-800 dark:text-red-200">
                          {threat.timestamp}
                        </span>
                        <span className="text-xs bg-red-600 text-white px-2 py-1 rounded">
                          {threat.threat_type || 'THREAT'}
                        </span>
                      </div>
                      <div className="text-sm text-gray-700 dark:text-gray-300 space-y-1">
                        <div>Flow: {formatFlowInfo(threat)}</div>
                        <div>Packets: {threat.packet_count || 0} | Bytes: {threat.total_bytes || 0}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* All Flows */}
        <Card>
          <CardHeader>
            <CardTitle>📊 All Flow Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px] w-full">
              <div className="space-y-2">
                {allFlows.length === 0 ? (
                  <p className="text-gray-500 text-center py-8">No flows detected</p>
                ) : (
                  allFlows.map((flow, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border ${
                        flow.is_threat
                          ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                          : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                      }`}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-sm font-semibold">
                          {flow.timestamp}
                        </span>
                        <span className={`text-xs px-2 py-1 rounded ${
                          flow.is_threat
                            ? 'bg-red-600 text-white'
                            : 'bg-green-600 text-white'
                        }`}>
                          {flow.is_threat ? (flow.threat_type || 'THREAT') : 'BENIGN'}
                        </span>
                      </div>
                      <div className="text-sm text-gray-700 dark:text-gray-300 space-y-1">
                        <div>Flow: {formatFlowInfo(flow)}</div>
                        <div>Packets: {flow.packet_count || 0} | Bytes: {flow.total_bytes || 0}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface PacketData {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_country?: string;
  dst_country?: string;
  protocol: string;
  src_port?: number;
  dst_port?: number;
  bytes_sent: number;
  bytes_received?: number;
  packets_sent?: number;
  packets_received?: number;
  application?: string;
  flags?: string[];
  ttl?: number;
  latency_ms?: number;
}

interface NetworkStatistics {
  total_connections: number;
  network_health_score: number;
  protocol_distribution: Record<string, number>;
  geographic_traffic: Record<string, number>;
  top_talkers: Record<string, number>;
  top_ports: Record<string, number>;
  application_usage: Record<string, number>;
}

const COLORS = [
  "#0088FE",
  "#00C49F",
  "#FFBB28",
  "#FF8042",
  "#8884D8",
  "#82CA9D",
];

export default function TrafficPage() {
  const [packets, setPackets] = useState<PacketData[]>([]);
  const [statistics, setStatistics] = useState<NetworkStatistics | null>(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");
  const wsRef = useRef<WebSocket | null>(null);

  const connectWebSocket = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    const ws = new WebSocket("ws://localhost:8000/ws/packets");
    wsRef.current = ws;

    ws.onopen = () => {
      setIsCapturing(true);
      setConnectionStatus("Connected - Capturing packets");
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.error) {
          setConnectionStatus(`Error: ${data.error}`);
          return;
        }

        if (data.traffic) {
          setPackets((prev) => [data.traffic, ...prev.slice(0, 49)]); // Keep last 50 packets
        }

        if (data.statistics) {
          setStatistics(data.statistics);
        }
      } catch (err) {
        console.error("Error parsing packet data:", err);
      }
    };

    ws.onclose = () => {
      setIsCapturing(false);
      setConnectionStatus("Disconnected");
      wsRef.current = null;
    };

    ws.onerror = (error) => {
      setConnectionStatus("Connection error");
      console.error("WebSocket error:", error);
    };
  };

  const disconnectWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }
  };

  const clearPackets = () => {
    setPackets([]);
  };

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Protocol distribution data for charts
  const protocolData = useMemo(() => {
    if (!statistics?.protocol_distribution) return [];
    return Object.entries(statistics.protocol_distribution)
      .filter(
        ([protocol, bytes]) => protocol && protocol.trim() !== "" && bytes > 0
      )
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([protocol, bytes]) => ({
        name: protocol,
        value: bytes,
        displayValue: `${(bytes / 1024).toFixed(1)} KB`,
      }));
  }, [statistics]);

  // Geographic traffic data
  const geoData = useMemo(() => {
    if (!statistics?.geographic_traffic) return [];
    return Object.entries(statistics.geographic_traffic)
      .filter(
        ([country, bytes]) => country && country.trim() !== "" && bytes > 0
      )
      .sort(([, a], [, b]) => b - a)
      .slice(0, 6)
      .map(([country, bytes]) => ({
        name: country,
        value: bytes,
        displayValue: `${(bytes / 1024).toFixed(1)} KB`,
      }));
  }, [statistics]);

  // Top talkers data
  const talkersData = useMemo(() => {
    if (!statistics?.top_talkers) return [];
    return Object.entries(statistics.top_talkers)
      .filter(([ip, bytes]) => ip && ip.trim() !== "" && bytes > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([ip, bytes]) => ({
        name: ip,
        value: bytes,
        displayValue: `${(bytes / 1024).toFixed(1)} KB`,
      }));
  }, [statistics]);

  // Top ports data
  const portsData = useMemo(() => {
    if (!statistics?.top_ports) return [];
    return Object.entries(statistics.top_ports)
      .filter(([port, count]) => port && port.trim() !== "" && count > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([port, count]) => ({
        name: port,
        value: count,
        displayValue: count.toString(),
      }));
  }, [statistics]);

  // Applications data
  const appsData = useMemo(() => {
    if (!statistics?.application_usage) return [];
    return Object.entries(statistics.application_usage)
      .filter(([app, bytes]) => app && app.trim() !== "" && bytes > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 6)
      .map(([app, bytes]) => ({
        name: app,
        value: bytes,
        displayValue: `${(bytes / 1024).toFixed(1)} KB`,
      }));
  }, [statistics]);

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-green-500 mb-2">
          🌐 Network Packet Capture
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Real-time packet capture and network analysis
        </p>
      </div>

      {/* Controls */}
      <div className="mb-6 flex gap-4">
        <Button
          onClick={connectWebSocket}
          disabled={isCapturing}
          className="bg-blue-600 hover:bg-blue-700"
        >
          Start Capture
        </Button>
        <Button
          onClick={disconnectWebSocket}
          disabled={!isCapturing}
          variant="destructive"
        >
          Stop Capture
        </Button>
        <Button onClick={clearPackets} variant="outline">
          Clear Packets
        </Button>
      </div>

      {/* Connection Status */}
      <div
        className={`flex items-center gap-4 p-4 rounded-lg shadow-md mb-6 ${
          isCapturing
            ? "bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800"
            : "bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800"
        }`}
      >
        <div className="relative">
          <div
            className={`w-3 h-3 rounded-full ${
              isCapturing ? "bg-green-500" : "bg-red-500"
            }`}
          />
          {isCapturing && (
            <div className="w-3 h-3 bg-green-400 rounded-full animate-ping absolute top-0 left-0" />
          )}
        </div>
        <div>
          <p
            className={`font-semibold ${
              isCapturing
                ? "text-green-800 dark:text-green-200"
                : "text-red-800 dark:text-red-200"
            }`}
          >
            {connectionStatus}
          </p>
        </div>
      </div>

      {/* Network Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Total Connections
            </p>
            <p className="text-2xl font-bold text-blue-600">
              {statistics?.total_connections || 0}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Network Health
            </p>
            <p className="text-2xl font-bold text-green-600">
              {statistics?.network_health_score?.toFixed(0) || 100}%
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Packets Captured
            </p>
            <p className="text-2xl font-bold text-purple-600">
              {packets.length}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Protocols
            </p>
            <p className="text-2xl font-bold text-orange-600">
              {protocolData.length}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Active IPs
            </p>
            <p className="text-2xl font-bold text-teal-600">
              {talkersData.length}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6 mb-6">
        <Card>
          <CardHeader>
            <CardTitle>🏆 Top Talkers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {talkersData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={talkersData} margin={{ bottom: 60 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      dataKey="name"
                      angle={-45}
                      textAnchor="end"
                      height={60}
                      fontSize={10}
                    />
                    <YAxis />
                    <Tooltip
                      formatter={(value: any) => [
                        `${(value / 1024).toFixed(1)} KB`,
                        "Data",
                      ]}
                    />
                    <Bar dataKey="value" fill="#0088FE" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No talker data yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Protocol Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>🔄 Protocol Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {protocolData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protocolData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) =>
                        `${name} (${(percent * 100).toFixed(0)}%)`
                      }
                      outerRadius={120}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {protocolData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={COLORS[index % COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: any) => [
                        `${(value / 1024).toFixed(1)} KB`,
                        "Data",
                      ]}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No protocol data yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Top Ports */}
        <Card>
          <CardHeader>
            <CardTitle>🔌 Top Ports</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {portsData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={portsData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="#00C49F" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No port data yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Additional Info Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Geographic Traffic */}
        <Card>
          <CardHeader>
            <CardTitle>🌍 Geographic Traffic</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {geoData.length > 0 ? (
                geoData.map((item, index) => (
                  <div
                    key={index}
                    className="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-800 rounded"
                  >
                    <span className="font-medium">{item.name}</span>
                    <span className="text-blue-600 font-semibold">
                      {item.displayValue}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-center text-gray-500 py-4">
                  No geographic data yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Applications */}
        <Card>
          <CardHeader>
            <CardTitle>📱 Applications</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {appsData.length > 0 ? (
                appsData.map((item, index) => (
                  <div
                    key={index}
                    className="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-800 rounded"
                  >
                    <span className="font-medium">{item.name}</span>
                    <span className="text-purple-600 font-semibold">
                      {item.displayValue}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-center text-gray-500 py-4">
                  No application data yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Packets Table */}
      <Card>
        <CardHeader>
          <CardTitle>📦 Recent Packets</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px] w-full">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Application</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>TTL</TableHead>
                  <TableHead>Country</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {packets.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={9}
                      className="text-center text-gray-500 py-8"
                    >
                      Waiting for packets...
                    </TableCell>
                  </TableRow>
                ) : (
                  packets.map((packet, idx) => (
                    <TableRow
                      key={idx}
                      className="hover:bg-gray-50 dark:hover:bg-gray-800"
                    >
                      <TableCell className="font-mono text-sm">
                        {packet.timestamp}
                      </TableCell>
                      <TableCell>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          packet.protocol?.toLowerCase() === 'tcp' ? 'text-blue-600' :
                          packet.protocol?.toLowerCase() === 'udp' ? 'text-orange-600' :
                          packet.protocol?.toLowerCase() === 'icmp' ? 'text-pink-600' :
                          packet.protocol?.toLowerCase() === 'arp' ? 'text-green-600' :
                          'text-gray-600'
                        }`}>
                          {packet.protocol || 'N/A'}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono">
                        {packet.src_ip}{packet.src_port ? `:${packet.src_port}` : ''}
                      </TableCell>
                      <TableCell className="font-mono">
                        {packet.dst_ip}{packet.dst_port ? `:${packet.dst_port}` : ''}
                      </TableCell>
                      <TableCell>{packet.application || "N/A"}</TableCell>
                      <TableCell className="text-xs">
                        {packet.flags && packet.flags.length > 0
                          ? packet.flags.join(", ")
                          : "N/A"}
                      </TableCell>
                      <TableCell className="font-mono">
                        {packet.bytes_sent || 'N/A'}
                      </TableCell>
                      <TableCell className="font-mono">
                        {packet.ttl || 'N/A'}
                      </TableCell>
                      <TableCell>
                        {packet.src_country || packet.dst_country || 'N/A'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

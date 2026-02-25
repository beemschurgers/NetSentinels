"use client";

import { useEffect, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Legend,
  Line,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@radix-ui/react-scroll-area";
import { Table } from "lucide-react";
import {
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useThreatDetection } from "@/contexts/ThreatDetectionContext";

interface Talker {
  ip: string;
  count: number;
}

interface TrafficData {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_country: string;
  dst_country: string;
  protocol: string;
  src_port: number;
  dst_port: number;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  application: string;
  flags: string[];
  ttl: number;
  latency_ms: number;
}

interface NetworkStatistics {
  total_connections: number;
  active_connections: number;
  top_talkers: Record<string, number>;
  protocol_distribution: Record<string, number>;
  top_ports: Record<string, number>;
  connection_distribution: Record<string, number>;
  geographic_traffic: Record<string, number>;
  application_usage: Record<string, number>;
  network_health_score: number;
}

interface Device {
  device_id: string;
  hostname: string;
  ip_address: string;
  mac_address: string;
  subnet: string;
  device_type: string;
  os: string;
  status: "online" | "offline";
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  network_utilization: number;
  uptime_hours: number;
  last_seen: string;
  timestamp: string;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  open_ports: number;
  running_services: number;
  patch_level: string;
  antivirus_status: string;
  firewall_status: string;
  location: string;
}

interface DeviceStatistics {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  device_uptime_percentage: number;
  average_cpu_usage: number;
  average_memory_usage: number;
  network_segments: Record<string, number>;
  device_types: Record<string, number>;
  os_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
  high_risk_devices: number;
  critical_devices: number;
  performance_timeline: Array<{
    timestamp: string;
    total_devices: number;
    online_devices: number;
    avg_cpu_usage: number;
    avg_memory_usage: number;
  }>;
  security_score: number;
  performance_score: number;
  top_cpu_consumers: Record<string, number>;
  top_memory_consumers: Record<string, number>;
  recent_alerts: string[];
}

interface Packet {
  time: string;
  protocol: string;
  src: string;
  dst: string;
  length: string;
}

interface DashboardThreatEvent {
  time: string;
  src: string;
  dst: string;
  type: string;
  severity: string;
  category: string;
  protocol: string;
  src_port?: number;
  dst_port?: number;
  src_country: string;
  bytes_transferred: number;
  flags: string[];
  ttl?: number;
  confidence: number;
  blocked: boolean;
  application: string;
}

interface ThreatStatistics {
  total_threats: number;
  recent_threats_10min: number;
  threats_per_minute: number;
  severity_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  protocol_distribution: Record<string, number>;
  hourly_pattern: Record<string, number>;
  top_sources: Record<string, number>;
  top_targets: Record<string, number>;
  geographic_distribution: Record<string, number>;
  threat_timeline: Array<{timestamp: string; count: number; severity: string}>;
  risk_score: number;
}

interface PacketStatistics {
  session_stats: {
    total_packets: number;
    unique_ips: number;
    protocols: Record<string, number>;
    avg_packet_size: number;
  };
}

export default function Dashboard() {
  const [data, setData] = useState<Talker[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [threats, setThreats] = useState<DashboardThreatEvent[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStatistics | null>(null);
  const [packetStats, setPacketStats] = useState<PacketStatistics | null>(null);
  const [riskScore, setRiskScore] = useState<number>(0);
  const [networkStats, setNetworkStats] = useState<NetworkStatistics | null>(null);
  const [trafficData, setTrafficData] = useState<TrafficData[]>([]);
  const [networkHealth, setNetworkHealth] = useState<number>(100);
  const [deviceStats, setDeviceStats] = useState<DeviceStatistics | null>(null);
  const [securityScore, setSecurityScore] = useState<number>(100);
  const [performanceScore, setPerformanceScore] = useState<number>(100);

  // Use the global threat detection context
  const { threats: globalThreats, stats: globalThreatStats, isConnected: threatDetectionConnected } = useThreatDetection();

  // Calculate threat-related metrics from global context
  const dashboardThreats = useMemo(() => {
    // Convert global threats to dashboard format for display
    return globalThreats.slice(0, 10).map((threat, index) => ({
      time: threat.timestamp,
      src: threat.endpoints?.[0]?.ip || "Unknown",
      dst: threat.endpoints?.[1]?.ip || "Unknown",
      type: threat.threat_type || "Unknown",
      severity: threat.is_threat ? "High" : "Low",
      category: "Network",
      protocol: "TCP", // Default for now
      src_port: threat.endpoints?.[0]?.port,
      dst_port: threat.endpoints?.[1]?.port,
      src_country: "Unknown",
      bytes_transferred: threat.total_bytes || 0,
      flags: [],
      confidence: 0.95,
      blocked: false,
      application: "Unknown"
    }));
  }, [globalThreats]);

  useEffect(() => {
    // Calculate risk score based on threat ratio
    const totalFlows = globalThreatStats.total_flows;
    const threatFlows = globalThreatStats.threat_flows;
    if (totalFlows > 0) {
      const threatRatio = threatFlows / totalFlows;
      const calculatedRiskScore = Math.min(100, Math.max(0, threatRatio * 100));
      setRiskScore(calculatedRiskScore);
      setSecurityScore(Math.max(0, 100 - calculatedRiskScore));
    }
  }, [globalThreatStats]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/packets");
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.status) {
          // Initial connection message
          console.log("Packet capture status:", data.status);
        } else if (data.type === "stats_update") {
          // Statistics update without new packet
          setPacketStats({ session_stats: data.statistics.session_stats });
        } else if (data.src && data.dst) {
          // New packet data
          const packet: Packet = {
            time: data.timestamp || new Date().toLocaleTimeString(),
            protocol: data.protocol,
            src: data.src,
            dst: data.dst,
            length: data.size?.toString() || "0"
          };
          setPackets((prev) => [...prev.slice(-100), packet]);
          
          if (data.session_stats) {
            setPacketStats({ session_stats: data.session_stats });
          }
        }
      } catch (err) {
        console.error("Invalid packet data:", err);
      }
    };
    return () => ws.close();
  }, []);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/top-talkers");

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.status) {
          // Initial connection message
          console.log("Top Talkers status:", data.status);
        } else if (data.type === "stats_update") {
          // Statistics update without new traffic
          setNetworkStats(data.statistics);
          setNetworkHealth(data.statistics.network_health_score);
          
          // Convert top_talkers object to array for chart
          const talkersArray = Object.entries(data.statistics.top_talkers || {}).map(([ip, bytes]) => ({
            ip,
            count: Math.round((bytes as number) / (1024 * 1024)) // Convert to MB
          }));
          setData(talkersArray);
        } else if (data.traffic) {
          // New traffic data
          setTrafficData(prev => [...prev.slice(-99), data.traffic]);
          setNetworkStats(data.statistics);
          setNetworkHealth(data.statistics.network_health_score);
          
          // Convert top_talkers object to array for chart
          const talkersArray = Object.entries(data.statistics.top_talkers || {}).map(([ip, bytes]) => ({
            ip,
            count: Math.round((bytes as number) / (1024 * 1024)) // Convert to MB
          }));
          setData(talkersArray);
        }
      } catch (err) {
        console.error("Invalid WebSocket data:", err);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);
    return () => ws.close();
  }, []);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/devices");

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.status) {
          // Initial connection message
          console.log("Device discovery status:", data.status);
        } else if (data.devices && data.statistics) {
          // Full device data update
          setDevices(data.devices);
          setDeviceStats(data.statistics);
          setSecurityScore(data.statistics.security_score);
          setPerformanceScore(data.statistics.performance_score);
        }
      } catch (err) {
        console.error("Invalid device data:", err);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);

    return () => ws.close();
  }, []);

  const COLORS = ["#10B981", "#3B82F6", "#F59E0B", "#EF4444", "#8B5CF6"];

  const severityColors = {
    Low: "#10B981",     // Green
    Medium: "#F59E0B",  // Yellow
    High: "#EF4444",    // Red
    Critical: "#7C2D12" // Dark Red
  };

  const getRiskScoreColor = (score: number) => {
    if (score < 25) return "#10B981"; // Green
    if (score < 50) return "#F59E0B"; // Yellow
    if (score < 75) return "#EF4444"; // Red
    return "#7C2D12"; // Dark Red
  };

  const getHealthScoreColor = (score: number) => {
    if (score >= 80) return "#10B981"; // Green
    if (score >= 60) return "#F59E0B"; // Yellow
    if (score >= 40) return "#EF4444"; // Red
    return "#7C2D12"; // Dark Red
  };

  const getDeviceRiskColor = (risk: string) => {
    switch (risk) {
      case "Low": return "#10B981";     // Green
      case "Medium": return "#F59E0B";  // Yellow
      case "High": return "#EF4444";    // Red
      case "Critical": return "#7C2D12"; // Dark Red
      default: return "#6B7280";       // Gray
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const severityData = useMemo(() => {
    if (!threatStats?.severity_distribution) return [];
    return Object.entries(threatStats.severity_distribution).map(([severity, count]) => ({
      name: severity,
      value: count,
      color: severityColors[severity as keyof typeof severityColors] || "#6B7280"
    }));
  }, [threatStats]);

  const categoryData = useMemo(() => {
    if (!threatStats?.category_distribution) return [];
    return Object.entries(threatStats.category_distribution).map(([category, count]) => ({
      name: category,
      value: count
    }));
  }, [threatStats]);

  const geographicData = useMemo(() => {
    if (!threatStats?.geographic_distribution) return [];
    return Object.entries(threatStats.geographic_distribution).map(([country, count]) => ({
      name: country,
      value: count
    }));
  }, [threatStats]);

  const topSourcesData = useMemo(() => {
    if (!threatStats?.top_sources) return [];
    return Object.entries(threatStats.top_sources)
      .slice(0, 10)
      .map(([ip, count]) => ({
        name: ip,
        value: count
      }));
  }, [threatStats]);

  const networkProtocolData = useMemo(() => {
    if (!networkStats?.protocol_distribution) return [];
    return Object.entries(networkStats.protocol_distribution).map(([protocol, bytes]) => ({
      name: protocol,
      value: Math.round((bytes as number) / (1024 * 1024)) // Convert to MB
    }));
  }, [networkStats]);

  const topPortsData = useMemo(() => {
    if (!networkStats?.top_ports) return [];
    return Object.entries(networkStats.top_ports)
      .slice(0, 10)
      .map(([port, count]) => ({
        name: `Port ${port}`,
        value: count
      }));
  }, [networkStats]);

  const applicationUsageData = useMemo(() => {
    if (!networkStats?.application_usage) return [];
    return Object.entries(networkStats.application_usage)
      .slice(0, 8)
      .map(([app, bytes]) => ({
        name: app,
        value: Math.round((bytes as number) / (1024 * 1024)) // Convert to MB
      }));
  }, [networkStats]);

  const deviceTypesData = useMemo(() => {
    if (!deviceStats?.device_types) return [];
    return Object.entries(deviceStats.device_types).map(([type, count]) => ({
      name: type,
      value: count
    }));
  }, [deviceStats]);

  const osDistributionData = useMemo(() => {
    if (!deviceStats?.os_distribution) return [];
    return Object.entries(deviceStats.os_distribution).map(([os, count]) => ({
      name: os,
      value: count
    }));
  }, [deviceStats]);

  const riskDistributionData = useMemo(() => {
    if (!deviceStats?.risk_distribution) return [];
    return Object.entries(deviceStats.risk_distribution).map(([risk, count]) => ({
      name: risk,
      value: count,
      color: getDeviceRiskColor(risk)
    }));
  }, [deviceStats]);

  const cpuConsumersData = useMemo(() => {
    if (!deviceStats?.top_cpu_consumers) return [];
    return Object.entries(deviceStats.top_cpu_consumers)
      .slice(0, 8)
      .map(([hostname, usage]) => ({
        name: hostname,
        value: usage
      }));
  }, [deviceStats]);

  const memoryConsumersData = useMemo(() => {
    if (!deviceStats?.top_memory_consumers) return [];
    return Object.entries(deviceStats.top_memory_consumers)
      .slice(0, 8)
      .map(([hostname, usage]) => ({
        name: hostname,
        value: usage
      }));
  }, [deviceStats]);

  const protocolData = useMemo(() => {
    const map: Record<string, number> = {};
    for (const pkt of packets) {
      const proto = pkt.protocol || "Unknown";
      map[proto] = (map[proto] || 0) + 1;
    }
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [packets]);

  const trafficOverTime = useMemo(() => {
    const map: Record<string, number> = {};
    for (const pkt of packets) {
      const ts = new Date(pkt.time).toLocaleTimeString();
      const len = parseInt(pkt.length) || 0;
      map[ts] = (map[ts] || 0) + len;
    }
    return Object.entries(map).map(([time, total]) => ({ time, total }));
  }, [packets]);

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-green-500 mb-4">
        Welcome to NetSentinel
      </h1>
      <p className="text-gray-600 dark:text-gray-400">
        Monitor your network in real time and detect anomalies using AI.
      </p>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" style={{ color: getRiskScoreColor(riskScore) }}>
              {riskScore.toFixed(1)}
            </div>
            <p className="text-xs text-muted-foreground">
              Network threat level
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Network Health</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" style={{ color: getHealthScoreColor(networkHealth) }}>
              {networkHealth.toFixed(0)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Network performance
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" style={{ color: getHealthScoreColor(securityScore) }}>
              {securityScore.toFixed(0)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Device security
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Performance</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" style={{ color: getHealthScoreColor(performanceScore) }}>
              {performanceScore.toFixed(0)}%
            </div>
            <p className="text-xs text-muted-foreground">
              System performance
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Devices</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {deviceStats?.online_devices || 0}/{deviceStats?.total_devices || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Online devices
            </p>
          </CardContent>
        </Card>
      </div>

      {/* <Card>
        <CardHeader>
          <CardTitle>Top Network Talkers</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <ScrollArea className="h-[400px] w-full">
              <table className="w-full text-sm min-w-[600px]">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="px-3 py-2 text-left font-medium">IP Address</th>
                    <th className="px-3 py-2 text-left font-medium">Total Traffic</th>
                    <th className="px-3 py-2 text-left font-medium">Traffic (MB)</th>
                    <th className="px-3 py-2 text-left font-medium">Percentage</th>
                    <th className="px-3 py-2 text-left font-medium">Last Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((talker, idx) => {
                    const totalBytes = talker.count * 1024 * 1024; // Convert back to bytes
                    const maxCount = Math.max(...data.map(t => t.count));
                    const percentage = maxCount > 0 ? ((talker.count / maxCount) * 100).toFixed(1) : '0.0';
                    
                    return (
                      <tr key={idx} className="border-b hover:bg-muted/10 transition-colors">
                        <td className="px-3 py-2 font-mono text-xs">{talker.ip}</td>
                        <td className="px-3 py-2">{formatBytes(totalBytes)}</td>
                        <td className="px-3 py-2 font-medium text-blue-600">{talker.count} MB</td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-gray-200 rounded-full h-2">
                              <div 
                                className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(parseFloat(percentage), 100)}%` }}
                              ></div>
                            </div>
                            <span className="text-xs">{percentage}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">
                          {new Date().toLocaleTimeString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollArea>
          </div>
        </CardContent>
      </Card> */}

      <Card>
        <CardHeader>
          <CardTitle>Device Monitoring</CardTitle>
          <p className="text-sm text-muted-foreground">
            Active network discovery - {devices.length} device{devices.length !== 1 ? 's' : ''} found
          </p>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <ScrollArea className="h-[300px] w-full">
              <table className="w-full text-sm min-w-[1000px]">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="px-3 py-2 text-left font-medium">Hostname</th>
                    <th className="px-3 py-2 text-left font-medium">IP</th>
                    <th className="px-3 py-2 text-left font-medium">MAC</th>
                    <th className="px-3 py-2 text-left font-medium">Type</th>
                    <th className="px-3 py-2 text-left font-medium">OS</th>
                    <th className="px-3 py-2 text-left font-medium">Status</th>
                    {/* <th className="px-3 py-2 text-left font-medium">CPU</th>
                    <th className="px-3 py-2 text-left font-medium">Memory</th> */}
                    <th className="px-3 py-2 text-left font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device, idx) => (
                    <tr key={device.device_id || idx} className="border-b hover:bg-muted/10 transition-colors">
                      <td className="px-3 py-2 font-medium truncate max-w-[120px]" title={device.hostname}>
                        {device.hostname}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{device.ip_address}</td>
                      <td className="px-3 py-2 font-mono text-xs truncate max-w-[100px]" title={device.mac_address}>
                        {device.mac_address}
                      </td>
                      <td className="px-3 py-2 truncate max-w-[100px]" title={device.device_type}>
                        {device.device_type}
                      </td>
                      <td className="px-3 py-2 truncate max-w-[120px]" title={device.os}>
                        {device.os}
                      </td>
                      <td className="px-3 py-2">
                        <span 
                          className={`px-2 py-1 rounded-full text-xs font-semibold whitespace-nowrap ${
                            device.status === "online" 
                              ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300" 
                              : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                          }`}
                        >
                          {device.status}
                        </span>
                      </td>
                      {/* <td className="px-3 py-2">
                        <span 
                          className={`font-medium ${
                            device.cpu_usage > 80 ? "text-red-500" : 
                            device.cpu_usage > 60 ? "text-yellow-500" : "text-green-500"
                          }`}
                        >
                          {device.cpu_usage.toFixed(1)}%
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span 
                          className={`font-medium ${
                            device.memory_usage > 85 ? "text-red-500" : 
                            device.memory_usage > 70 ? "text-yellow-500" : "text-green-500"
                          }`}
                        >
                          {device.memory_usage.toFixed(1)}%
                        </span>
                      </td> */}
                      <td className="px-3 py-2">
                        <span 
                          className="px-2 py-1 rounded-full text-xs font-semibold whitespace-nowrap"
                          style={{ 
                            backgroundColor: getDeviceRiskColor(device.risk_level) + "20",
                            color: getDeviceRiskColor(device.risk_level)
                          }}
                        >
                          {device.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Device Types Distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={deviceTypesData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={100}
                  innerRadius={60}
                  label
                >
                  {deviceTypesData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Operating System Distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={osDistributionData} margin={{ bottom: 60 }}>
                <XAxis 
                  dataKey="name" 
                  angle={-45} 
                  textAnchor="end" 
                  height={80}
                  fontSize={12}
                  interval={0}
                />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="value" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Network Protocol Usage</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={networkProtocolData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={100}
                  innerRadius={60}
                  label
                >
                  {networkProtocolData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => [`${value} MB`, 'Network Usage']} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div> */}

      <div className="grid grid-cols-1 md:grid-cols-1 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Device Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskDistributionData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={100}
                  innerRadius={60}
                  label
                >
                  {riskDistributionData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* <Card>
          <CardHeader>
            <CardTitle>Top CPU Consumers</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={cpuConsumersData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} label={{ value: '%', angle: -90, position: 'insideLeft' }} />
                <Tooltip formatter={(value) => [`${value}%`, 'CPU Usage']} />
                <Bar dataKey="value" fill="#EF4444" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card> */}
      </div>


    </div>
  );
}

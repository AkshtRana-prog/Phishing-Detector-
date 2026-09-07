"use client";

import React from "react";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  BarChart, 
  Bar, 
  Cell,
  PieChart,
  Pie
} from "recharts";
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  Activity, 
  FileDown,
  TrendingUp,
  Clock
} from "lucide-react";
import { StatusBadge } from "../ui/StatusBadge";
import { ThreatMeter } from "../ui/ThreatMeter";

interface AnalyticsData {
  total_scans: number;
  status_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  vector_distribution: Record<string, number>;
  time_trends: { name: string; Phishing: number; Deepfake: number; Exploits: number; Safe: number }[];
}

interface AnalyticsWorkspaceProps {
  analytics: AnalyticsData;
  onDownloadGlobalReport: () => void;
}

export function AnalyticsWorkspace({
  analytics,
  onDownloadGlobalReport,
}: AnalyticsWorkspaceProps) {
  const statusData = [
    { name: "Phishing", count: analytics.status_distribution?.PHISHING || 0, color: "var(--state-crit-border)" },
    { name: "Deepfake", count: analytics.status_distribution?.DEEPFAKE || 0, color: "oklch(64% 0.18 55)" },
    { name: "Suspicious", count: analytics.status_distribution?.SUSPICIOUS || 0, color: "var(--state-susp-border)" },
    { name: "Safe", count: analytics.status_distribution?.SAFE || 0, color: "var(--state-safe-border)" },
  ];

  const vectorData = [
    { name: "URL", count: analytics.vector_distribution?.URL || 0, color: "var(--accent-base)" },
    { name: "Email", count: analytics.vector_distribution?.Email || 0, color: "oklch(62% 0.16 295)" },
    { name: "Log / PCAP", count: analytics.vector_distribution?.Log || 0, color: "oklch(60% 0.15 145)" },
    { name: "Deepfake", count: analytics.vector_distribution?.Deepfake || 0, color: "oklch(64% 0.18 55)" },
  ];

  const severityData = [
    { name: "Critical", count: analytics.severity_distribution?.CRITICAL || 0, color: "var(--state-crit-border)" },
    { name: "High", count: analytics.severity_distribution?.HIGH || 0, color: "oklch(65% 0.16 40)" },
    { name: "Medium", count: analytics.severity_distribution?.MEDIUM || 0, color: "var(--state-susp-border)" },
    { name: "Low", count: analytics.severity_distribution?.LOW || 0, color: "var(--state-safe-border)" },
  ];

  return (
    <div className="flex flex-col gap-6" data-od-id="analytics-workspace">
      {/* 1. HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Intelligence // Threat Telemetry
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">SYSTEM AGGREGATE</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Forensic Analytics & Incident Dynamics
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Macro analysis of ingested threat vectors, verdict classifications, and incident velocity across the database.
          </p>
        </div>

        <button
          type="button"
          onClick={onDownloadGlobalReport}
          className="px-3.5 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition flex items-center gap-2 shrink-0 shadow-sm"
        >
          <FileDown className="h-4 w-4" />
          <span>Export Summary Report (PDF)</span>
        </button>
      </div>

      {/* 2. TIME TRENDS CHART */}
      <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-4">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-[var(--accent-base)]" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
              Threat Velocity Timeline
            </h2>
          </div>
          <span className="text-[10px] font-mono text-[var(--fg-muted)]">
            30-DAY TEMPORAL DISTRIBUTION
          </span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={analytics.time_trends}>
              <defs>
                <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--state-crit-border)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--state-crit-border)" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="dfGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#d946ef" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#d946ef" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="name" stroke="var(--fg-muted)" fontSize={10} tickLine={false} />
              <YAxis stroke="var(--fg-muted)" fontSize={10} tickLine={false} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: "var(--bg-surface)", 
                  borderColor: "var(--border-subtle)", 
                  borderRadius: "6px",
                  fontSize: "11px",
                  fontFamily: "monospace"
                }} 
              />
              <Area type="monotone" dataKey="Phishing" stroke="var(--state-crit-border)" fillOpacity={1} fill="url(#phishGrad)" />
              <Area type="monotone" dataKey="Deepfake" stroke="#d946ef" fillOpacity={1} fill="url(#dfGrad)" />
              <Area type="monotone" dataKey="Safe" stroke="var(--state-safe-border)" fillOpacity={0.1} fill="var(--state-safe-border)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 3. MACRO DISTRIBUTIONS (3 COLS) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Classification Distribution */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-3">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
            Classification Distribution
          </span>
          <div className="flex flex-col gap-2 font-mono text-xs pt-1">
            {statusData.map((item) => (
              <div key={item.name} className="flex flex-col gap-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-[var(--fg-secondary)]">{item.name}</span>
                  <span className="font-bold text-[var(--fg-primary)]">{item.count}</span>
                </div>
                <div className="h-1.5 w-full bg-[var(--bg-elevated)] rounded overflow-hidden">
                  <div 
                    className="h-full rounded transition-all" 
                    style={{ 
                      width: `${analytics.total_scans ? (item.count / analytics.total_scans) * 100 : 0}%`,
                      backgroundColor: item.color
                    }} 
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vector Distribution */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-3">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
            Vector Distribution
          </span>
          <div className="flex flex-col gap-2 font-mono text-xs pt-1">
            {vectorData.map((item) => (
              <div key={item.name} className="flex flex-col gap-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-[var(--fg-secondary)]">{item.name}</span>
                  <span className="font-bold text-[var(--fg-primary)]">{item.count}</span>
                </div>
                <div className="h-1.5 w-full bg-[var(--bg-elevated)] rounded overflow-hidden">
                  <div 
                    className="h-full rounded transition-all" 
                    style={{ 
                      width: `${analytics.total_scans ? (item.count / analytics.total_scans) * 100 : 0}%`,
                      backgroundColor: item.color
                    }} 
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-3">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
            Severity Severity Distribution
          </span>
          <div className="flex flex-col gap-2 font-mono text-xs pt-1">
            {severityData.map((item) => (
              <div key={item.name} className="flex flex-col gap-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-[var(--fg-secondary)]">{item.name}</span>
                  <span className="font-bold text-[var(--fg-primary)]">{item.count}</span>
                </div>
                <div className="h-1.5 w-full bg-[var(--bg-elevated)] rounded overflow-hidden">
                  <div 
                    className="h-full rounded transition-all" 
                    style={{ 
                      width: `${analytics.total_scans ? (item.count / analytics.total_scans) * 100 : 0}%`,
                      backgroundColor: item.color
                    }} 
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}

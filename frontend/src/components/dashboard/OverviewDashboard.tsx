"use client";

import React, { useState, useMemo } from "react";
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  Search, 
  Link as LinkIcon, 
  Mail, 
  Terminal, 
  Video, 
  ArrowRight, 
  FileDown, 
  RefreshCw, 
  Layers, 
  Server, 
  Cpu, 
  Database, 
  ExternalLink,
  BrainCircuit,
  Filter
} from "lucide-react";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  BarChart, 
  Bar, 
  Cell 
} from "recharts";
import { StatusBadge } from "../ui/StatusBadge";
import { ThreatMeter } from "../ui/ThreatMeter";

interface Incident {
  id: string;
  timestamp: string;
  vector_type: string;
  status: string;
  severity: string;
  threat_score: number;
  target_input: string;
}

interface AnalyticsData {
  total_scans: number;
  status_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  vector_distribution: Record<string, number>;
  time_trends: { name: string; Phishing: number; Deepfake: number; Exploits: number; Safe: number }[];
}

interface OverviewDashboardProps {
  incidents: Incident[];
  analytics: AnalyticsData;
  loadingList: boolean;
  onSelectIncident: (id: string) => void;
  onNavigateTab: (tab: string) => void;
  onDeleteIncident: (id: string) => void;
  onTrainML: (id: string, label: string) => void;
  onDownloadReport: (id: string) => void;
  userEmail: string | null;
  apiOffline: boolean;
}

export function OverviewDashboard({
  incidents,
  analytics,
  loadingList,
  onSelectIncident,
  onNavigateTab,
  onDeleteIncident,
  onTrainML,
  onDownloadReport,
  userEmail,
  apiOffline,
}: OverviewDashboardProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [vectorFilter, setVectorFilter] = useState<string>("ALL");

  // Real KPI calculations from backend database
  const totalScans = analytics.total_scans || incidents.length;
  const phishingCount = (analytics.status_distribution?.PHISHING || 0) + (analytics.status_distribution?.DEEPFAKE || 0);
  const suspiciousCount = analytics.status_distribution?.SUSPICIOUS || 0;
  const safeCount = analytics.status_distribution?.SAFE || 0;
  const pendingCount = incidents.filter(i => i.status === "PENDING").length;
  const criticalCount = incidents.filter(i => i.severity === "CRITICAL").length;

  // Filtered investigations list
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesVector = vectorFilter === "ALL" || inc.vector_type.toUpperCase() === vectorFilter.toUpperCase();
      const query = searchQuery.toLowerCase().trim();
      const matchesSearch = !query || 
        inc.target_input.toLowerCase().includes(query) ||
        inc.id.toLowerCase().includes(query) ||
        inc.status.toLowerCase().includes(query) ||
        inc.vector_type.toLowerCase().includes(query);
      return matchesVector && matchesSearch;
    });
  }, [incidents, vectorFilter, searchQuery]);

  // Vector chart dataset
  const vectorChartData = useMemo(() => {
    const v = analytics.vector_distribution || {};
    return [
      { name: "URL", count: v.URL || incidents.filter(i => i.vector_type === "URL").length, color: "var(--accent-base)" },
      { name: "Email", count: v.Email || incidents.filter(i => i.vector_type === "Email").length, color: "oklch(62% 0.16 295)" },
      { name: "Log / PCAP", count: v.Log || incidents.filter(i => i.vector_type === "Log").length, color: "oklch(60% 0.15 145)" },
      { name: "Deepfake", count: v.Deepfake || incidents.filter(i => i.vector_type === "Deepfake").length, color: "oklch(64% 0.18 55)" },
    ];
  }, [analytics.vector_distribution, incidents]);

  return (
    <div className="flex flex-col gap-6" data-od-id="overview-dashboard">
      {/* 1. OPERATIONAL SITUATION STRIP */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              SOC Command Console
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">
              {apiOffline ? "OFFLINE / DISCONNECTED" : "TELEMETRY SYNCHRONIZED"}
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Security Operations & Threat Triage
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Active multi-vector threat detection pipeline monitoring URL, Email, Syslog/PCAP, and Media artifacts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => onNavigateTab("investigate")}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded bg-[var(--accent-base)] text-white hover:bg-[var(--accent-hover)] transition shadow-sm active:scale-[0.98] cursor-pointer"
            data-od-id="new-investigation-btn"
          >
            <Shield className="h-3.5 w-3.5" />
            <span>Launch Investigation</span>
          </button>
        </div>
      </div>

      {/* 2. REAL TELEMETRY METRIC TILES */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between h-28">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-[var(--fg-muted)]">
              Total Audited Scans
            </span>
            <Layers className="h-4 w-4 text-[var(--fg-muted)]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[var(--fg-primary)] tabular-nums">
              {totalScans}
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">records in database</span>
          </div>
          <div className="text-[11px] font-mono text-[var(--fg-secondary)]">
            {safeCount} classified legitimate
          </div>
        </div>

        {/* Confirmed Phishing & Threats */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between h-28">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-[var(--state-crit-fg)]">
              Malicious Threats
            </span>
            <ShieldAlert className="h-4 w-4 text-[var(--state-crit-fg)]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[var(--state-crit-fg)] tabular-nums">
              {phishingCount}
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">confirmed malicious</span>
          </div>
          <div className="text-[11px] font-mono text-[var(--state-crit-fg)]">
            {criticalCount} rated Critical severity
          </div>
        </div>

        {/* Suspicious Anomalies */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between h-28">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-[var(--state-susp-fg)]">
              Suspicious Indicators
            </span>
            <AlertTriangle className="h-4 w-4 text-[var(--state-susp-fg)]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[var(--state-susp-fg)] tabular-nums">
              {suspiciousCount}
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">flagged for review</span>
          </div>
          <div className="text-[11px] font-mono text-[var(--fg-muted)]">
            Elevated typosquat / entropy markers
          </div>
        </div>

        {/* Pending Triage */}
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between h-28">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-[var(--state-info-fg)]">
              Pending Queue
            </span>
            <Clock className="h-4 w-4 text-[var(--state-info-fg)]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[var(--fg-primary)] tabular-nums">
              {pendingCount}
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">active Celery tasks</span>
          </div>
          <div className="text-[11px] font-mono text-[var(--fg-secondary)]">
            {pendingCount === 0 ? "All tasks completed" : "Worker analysis in progress"}
          </div>
        </div>
      </div>

      {/* 3. INVESTIGATION LAUNCHPAD (4 SPECIALIZED VECTORS) */}
      <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
              Detection Vector Workspaces
            </h2>
            <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
              Direct ingress channels for deep structural, heuristic, and machine-learning inspection.
            </p>
          </div>
          <span className="text-[10px] font-mono text-[var(--fg-muted)] uppercase">
            4 Dedicated Analysis Engines
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Vector 1: URL */}
          <div
            onClick={() => onNavigateTab("url_analysis")}
            className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] hover:bg-[var(--bg-hover)] transition cursor-pointer flex flex-col justify-between group"
            data-od-id="vector-card-url"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded bg-[var(--accent-surface)] text-[var(--accent-base)]">
                  <LinkIcon className="h-4 w-4" />
                </div>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">Passive & Heuristic</span>
              </div>
              <h3 className="text-xs font-bold text-[var(--fg-primary)] group-hover:text-[var(--accent-base)] transition">
                URL & Domain Forensics
              </h3>
              <p className="text-[11px] text-[var(--fg-secondary)] mt-1 line-clamp-2">
                Typosquatting Levenshtein distance, Punycode encoding, SSL validation, and Naive Bayes domain scoring.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--accent-base)]">
              <span>Launch URL Audit</span>
              <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition" />
            </div>
          </div>

          {/* Vector 2: Email */}
          <div
            onClick={() => onNavigateTab("email_analysis")}
            className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] hover:bg-[var(--bg-hover)] transition cursor-pointer flex flex-col justify-between group"
            data-od-id="vector-card-email"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded bg-purple-500/10 text-purple-400">
                  <Mail className="h-4 w-4" />
                </div>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">RFC 822 / EML</span>
              </div>
              <h3 className="text-xs font-bold text-[var(--fg-primary)] group-hover:text-[var(--accent-base)] transition">
                Email Authentication Audit
              </h3>
              <p className="text-[11px] text-[var(--fg-secondary)] mt-1 line-clamp-2">
                SPF, DKIM, DMARC alignment, display name spoofing, embedded URL extraction, and DistilRoBERTa NLP.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--accent-base)]">
              <span>Analyze EML Message</span>
              <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition" />
            </div>
          </div>

          {/* Vector 3: Log & PCAP */}
          <div
            onClick={() => onNavigateTab("log_analysis")}
            className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] hover:bg-[var(--bg-hover)] transition cursor-pointer flex flex-col justify-between group"
            data-od-id="vector-card-log"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded bg-emerald-500/10 text-emerald-400">
                  <Terminal className="h-4 w-4" />
                </div>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">PCAP & Syslog</span>
              </div>
              <h3 className="text-xs font-bold text-[var(--fg-primary)] group-hover:text-[var(--accent-base)] transition">
                Log & Network Capture
              </h3>
              <p className="text-[11px] text-[var(--fg-secondary)] mt-1 line-clamp-2">
                PCAP volumetric packet flood, reconnaissance port sweep, SQLi, command injection, and brute-force auth.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--accent-base)]">
              <span>Ingest Log / PCAP</span>
              <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition" />
            </div>
          </div>

          {/* Vector 4: Deepfake Media */}
          <div
            onClick={() => onNavigateTab("media_analysis")}
            className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] hover:bg-[var(--bg-hover)] transition cursor-pointer flex flex-col justify-between group"
            data-od-id="vector-card-media"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded bg-amber-500/10 text-amber-400">
                  <Video className="h-4 w-4" />
                </div>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">Audio / Video</span>
              </div>
              <h3 className="text-xs font-bold text-[var(--fg-primary)] group-hover:text-[var(--accent-base)] transition">
                Deepfake Media Forensics
              </h3>
              <p className="text-[11px] text-[var(--fg-secondary)] mt-1 line-clamp-2">
                Shannon acoustic entropy, Wav2Vec 2.0 voice synthesis markers, visual artifacts, and AI container tags.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--accent-base)]">
              <span>Verify Media Integrity</span>
              <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition" />
            </div>
          </div>
        </div>
      </div>

      {/* 4. DUAL TELEMETRY VISUALIZATIONS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Vector Distribution (1 Col) */}
        <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                Threat Vector Ingress
              </h2>
              <span className="text-[10px] font-mono text-[var(--fg-muted)]">REAL COUNTS</span>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] mb-4">
              Distribution of threat evaluations by ingress vector.
            </p>

            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={vectorChartData} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={80} tick={{ fill: "var(--fg-secondary)", fontSize: 11, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: "var(--bg-elevated)", 
                      borderColor: "var(--border-subtle)", 
                      color: "var(--fg-primary)",
                      fontSize: 12,
                      fontFamily: "monospace"
                    }} 
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {vectorChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-3 border-t border-[var(--border-subtle)] text-[11px] font-mono">
            {vectorChartData.map((v) => (
              <div key={v.name} className="flex items-center justify-between text-[var(--fg-secondary)]">
                <span>{v.name}:</span>
                <span className="font-bold text-[var(--fg-primary)] tabular-nums">{v.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Velocity Timeline (2 Cols) */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                Threat Activity Velocity
              </h2>
              <span className="text-[10px] font-mono text-[var(--fg-muted)]">DATABASE TIMELINE</span>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] mb-4">
              Historical incident velocity by detection outcome calculated from timestamps.
            </p>

            <div className="h-44 w-full">
              {analytics.time_trends && analytics.time_trends.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={analytics.time_trends} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="phishingGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--state-crit-fg)" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="var(--state-crit-fg)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--state-safe-fg)" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="var(--state-safe-fg)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="name" tick={{ fill: "var(--fg-muted)", fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "var(--fg-muted)", fontSize: 10, fontFamily: "monospace" }} axisLine={false} tickLine={false} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: "var(--bg-elevated)", 
                        borderColor: "var(--border-subtle)", 
                        color: "var(--fg-primary)",
                        fontSize: 12,
                        fontFamily: "monospace"
                      }} 
                    />
                    <Area type="monotone" dataKey="Phishing" stroke="var(--state-crit-fg)" fillOpacity={1} fill="url(#phishingGrad)" strokeWidth={1.5} />
                    <Area type="monotone" dataKey="Safe" stroke="var(--state-safe-fg)" fillOpacity={1} fill="url(#safeGrad)" strokeWidth={1.5} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-[var(--fg-muted)] font-mono">
                  No incident timeline recorded yet. Execute scans to populate activity.
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between pt-3 border-t border-[var(--border-subtle)] text-[11px] font-mono text-[var(--fg-muted)]">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[var(--state-crit-fg)]" />
                <span>Phishing / Malicious</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[var(--state-safe-fg)]" />
                <span>Legitimate / Safe</span>
              </span>
            </div>
            <span>Auto-aggregated from incident database</span>
          </div>
        </div>
      </div>

      {/* 5. RECENT INVESTIGATIONS & TRIAGE TABLE */}
      <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4 pb-3 border-b border-[var(--border-subtle)]">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
              Recent Investigations & Triage Queue
            </h2>
            <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
              Showing {filteredIncidents.length} of {incidents.length} security events stored in database.
            </p>
          </div>

          {/* Filters & Search */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--fg-muted)]" />
              <input
                type="text"
                placeholder="Filter targets, IDs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded text-[var(--fg-primary)] placeholder-[var(--fg-muted)] focus:outline-none focus:border-[var(--border-focus)] font-mono w-48"
              />
            </div>

            {/* Vector filter pills */}
            <div className="flex items-center gap-1 p-0.5 bg-[var(--bg-elevated)] rounded border border-[var(--border-subtle)]">
              {["ALL", "URL", "EMAIL", "LOG", "DEEPFAKE"].map((vec) => (
                <button
                  key={vec}
                  type="button"
                  onClick={() => setVectorFilter(vec)}
                  className={`px-2 py-1 text-[10px] font-mono font-semibold rounded cursor-pointer transition ${
                    vectorFilter === vec
                      ? "bg-[var(--accent-base)] text-white"
                      : "text-[var(--fg-secondary)] hover:text-[var(--fg-primary)]"
                  }`}
                >
                  {vec}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" data-od-id="investigations-table">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] text-[10px] font-mono text-[var(--fg-muted)] uppercase tracking-wider">
                <th className="py-2.5 px-3">Vector</th>
                <th className="py-2.5 px-3">Target Artifact</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3 w-40">Threat Score</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)] font-mono">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[var(--fg-muted)]">
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="h-8 w-8 text-[var(--fg-muted)] stroke-1" />
                      <span className="text-xs font-semibold">No threat incidents found matching current filter</span>
                      <span className="text-[11px]">Execute a new analysis from the launchpad above.</span>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr 
                    key={inc.id}
                    className="hover:bg-[var(--bg-hover)] transition group"
                  >
                    {/* Vector */}
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--fg-primary)]">
                        {inc.vector_type === "URL" && <LinkIcon className="h-3.5 w-3.5 text-[var(--accent-base)]" />}
                        {inc.vector_type === "Email" && <Mail className="h-3.5 w-3.5 text-purple-400" />}
                        {inc.vector_type === "Log" && <Terminal className="h-3.5 w-3.5 text-emerald-400" />}
                        {inc.vector_type === "Deepfake" && <Video className="h-3.5 w-3.5 text-amber-400" />}
                        <span>{inc.vector_type}</span>
                      </span>
                    </td>

                    {/* Target Input */}
                    <td className="py-3 px-3 max-w-xs truncate" title={inc.target_input}>
                      <span className="text-[var(--fg-primary)] font-mono text-[11px] block truncate">
                        {inc.target_input}
                      </span>
                      <span className="text-[9px] text-[var(--fg-muted)] block font-mono truncate">
                        ID: {inc.id.slice(0, 8)}...
                      </span>
                    </td>

                    {/* Status Verdict */}
                    <td className="py-3 px-3">
                      <StatusBadge status={inc.status} size="sm" />
                    </td>

                    {/* Threat Score */}
                    <td className="py-3 px-3">
                      <ThreatMeter score={inc.threat_score} size="sm" showLabel={false} />
                      <div className="flex justify-between items-center text-[9px] text-[var(--fg-muted)] mt-0.5">
                        <span>{inc.severity}</span>
                        <span className="font-bold tabular-nums">{inc.threat_score}/100</span>
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-3 text-[11px] text-[var(--fg-secondary)] tabular-nums whitespace-nowrap">
                      {inc.timestamp}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => onSelectIncident(inc.id)}
                          className="px-2.5 py-1 text-[10px] font-semibold rounded bg-[var(--bg-elevated)] hover:bg-[var(--bg-active)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition cursor-pointer"
                          title="Inspect incident evidence and timeline"
                        >
                          Inspect
                        </button>
                        <button
                          type="button"
                          onClick={() => onDownloadReport(inc.id)}
                          className="p-1 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-elevated)] transition cursor-pointer"
                          title="Download native ReportLab PDF report"
                        >
                          <FileDown className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 6. DETECTION ENGINE STATUS & SYSTEM HEALTH */}
      <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[var(--accent-base)]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
              Detection Subsystem Health & Forensics Engines
            </h3>
          </div>
          <span className="text-[10px] font-mono text-[var(--fg-muted)]">FASTAPI + CELERY + POSTGRESQL</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono">
          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">API Gateway</span>
            <span className="font-bold text-[var(--state-safe-fg)] flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--state-safe-fg)]" />
              <span>:8000 Online</span>
            </span>
          </div>

          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">Celery Broker</span>
            <span className="font-bold text-[var(--state-safe-fg)] flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--state-safe-fg)]" />
              <span>Redis Active</span>
            </span>
          </div>

          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">Self-Learning ML</span>
            <span className="font-bold text-[var(--state-safe-fg)] flex items-center gap-1 mt-0.5">
              <BrainCircuit className="h-3 w-3 text-[var(--state-safe-fg)]" />
              <span>Naive Bayes</span>
            </span>
          </div>

          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">Email NLP Model</span>
            <span className="font-bold text-[var(--accent-base)] flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-base)]" />
              <span>DistilRoBERTa</span>
            </span>
          </div>

          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">Deepfake Forensics</span>
            <span className="font-bold text-[var(--state-safe-fg)] flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--state-safe-fg)]" />
              <span>Wav2Vec / Entropy</span>
            </span>
          </div>

          <div className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[9px] text-[var(--fg-muted)] uppercase block">Report Engine</span>
            <span className="font-bold text-[var(--state-safe-fg)] flex items-center gap-1 mt-0.5">
              <FileDown className="h-3 w-3 text-[var(--state-safe-fg)]" />
              <span>ReportLab PDF</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

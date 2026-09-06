"use client";

import React, { useState, useRef } from "react";
import { 
  Terminal, 
  Upload, 
  RefreshCw, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  FileDown, 
  FileText, 
  CheckCircle2, 
  Cpu,
  Layers,
  Network
} from "lucide-react";
import { StatusBadge } from "../ui/StatusBadge";
import { ThreatMeter } from "../ui/ThreatMeter";

interface Evidence {
  key: string;
  value: string;
}

interface IncidentDetail {
  id: string;
  timestamp: string;
  vector_type: string;
  status: string;
  severity: string;
  threat_score: number;
  target_input: string;
  evidences: Evidence[];
  remediations: string[];
}

interface LogAnalysisWorkspaceProps {
  logFile: File | null;
  setLogFile: (file: File | null) => void;
  logScanning: boolean;
  onStartScan: (e: React.FormEvent) => Promise<void>;
  selectedIncident: IncidentDetail | null;
  onDownloadReport: (id: string) => void;
  onTrainML: (id: string, label: string) => void;
}

export function LogAnalysisWorkspace({
  logFile,
  setLogFile,
  logScanning,
  onStartScan,
  selectedIncident,
  onDownloadReport,
  onTrainML,
}: LogAnalysisWorkspaceProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const allowedExtensions = [".log", ".txt", ".json", ".pcap", ".csv"];

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const f = e.dataTransfer.files[0];
      const lower = f.name.toLowerCase();
      if (allowedExtensions.some(ext => lower.endsWith(ext))) {
        setLogFile(f);
      } else {
        alert("Please select a supported log or network capture file (.log, .txt, .json, .pcap, .csv).");
      }
    }
  };

  const hasResult = selectedIncident && selectedIncident.vector_type === "Log" && !logScanning;

  return (
    <div className="flex flex-col gap-6" data-od-id="log-analysis-workspace">
      {/* 1. WORKSPACE HEADER & SCOPE */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Vector // Log & Network Capture
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">PACKET & SYSLOG FORENSICS</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Network Packet & Server Log Forensics
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Ingest binary PCAP/PCAPNG packet frames or raw server logs to detect volumetric floods, port scans, SQL injection, RCE, and auth brute-force.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[var(--fg-muted)]">
          <span className="px-2 py-1 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            Formats: PCAP, LOG, TXT, JSON, CSV
          </span>
        </div>
      </div>

      {/* 2. FILE INGESTION DROPZONE */}
      <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <form onSubmit={onStartScan} className="flex flex-col gap-4">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center gap-3 transition cursor-pointer ${
              dragOver
                ? "border-[var(--accent-base)] bg-[var(--accent-surface)]"
                : logFile
                ? "border-emerald-500/40 bg-emerald-500/5"
                : "border-[var(--border-subtle)] bg-[var(--bg-elevated)] hover:border-[var(--border-strong)]"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.json,.pcap,.csv"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  setLogFile(e.target.files[0]);
                }
              }}
            />

            <div className="p-3 rounded-full bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-emerald-400 shadow-sm">
              <Network className="h-6 w-6" />
            </div>

            <div className="text-center">
              {logFile ? (
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-emerald-400" />
                  <span className="text-xs font-bold font-mono text-[var(--fg-primary)]">
                    {logFile.name}
                  </span>
                  <span className="text-[10px] font-mono text-[var(--fg-muted)]">
                    ({(logFile.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
              ) : (
                <>
                  <p className="text-xs font-semibold text-[var(--fg-primary)]">
                    Drop PCAP capture or server log file here, or click to browse
                  </p>
                  <p className="text-[11px] text-[var(--fg-muted)] font-mono mt-1">
                    Accepts Wireshark/tcpdump .pcap captures, Nginx/Apache logs, syslog, or auditd traces
                  </p>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="text-[10px] font-mono text-[var(--fg-muted)]">
              Analyzes: SYN Flood · Recon Port Sweeps · SQLi / XSS · Command Injection (`/bin/sh`) · Sudo PrivEsc
            </div>

            <div className="flex items-center gap-2">
              {logFile && (
                <button
                  type="button"
                  onClick={() => setLogFile(null)}
                  className="px-3 py-2 text-xs font-mono text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition cursor-pointer"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                disabled={!logFile || logScanning}
                className="px-5 py-2.5 bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white font-semibold text-xs rounded transition shadow-sm flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                data-od-id="start-log-scan-btn"
              >
                {logScanning ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Parsing Telemetry...</span>
                  </>
                ) : (
                  <>
                    <Upload className="h-3.5 w-3.5" />
                    <span>Start Log Audit</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* 3. SCANNING PROGRESS */}
      {logScanning && (
        <div className="p-6 rounded-lg bg-[var(--bg-surface)] border border-emerald-500/30 flex items-center gap-4 animate-pulse">
          <RefreshCw className="h-6 w-6 text-emerald-400 animate-spin shrink-0" />
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-bold text-[var(--fg-primary)] font-mono">
              Parsing Packet Frames & Event Signatures...
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">
              Correlating source IPs, port access patterns, brute-force anomalies, and signature matching for SQLi and privilege escalation.
            </span>
          </div>
        </div>
      )}

      {/* 4. REAL FORENSIC RESULTS */}
      {hasResult && selectedIncident && (
        <div className="flex flex-col gap-5">
          {/* Main Verdict Banner */}
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                Evaluated Artifact
              </span>
              <span className="text-sm font-bold font-mono text-[var(--fg-primary)] block break-all">
                {selectedIncident.target_input}
              </span>
              <span className="text-[10px] font-mono text-[var(--fg-muted)] block mt-1">
                Incident ID: {selectedIncident.id} · Timestamp: {selectedIncident.timestamp}
              </span>
            </div>

            <div className="flex items-center gap-6 shrink-0 pt-3 md:pt-0 border-t md:border-t-0 border-[var(--border-subtle)]">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                  Classification
                </span>
                <StatusBadge status={selectedIncident.status} size="lg" />
              </div>

              <div className="border-l border-[var(--border-subtle)] pl-6">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                  Threat Severity
                </span>
                <ThreatMeter score={selectedIncident.threat_score} size="md" className="w-36" />
              </div>
            </div>
          </div>

          {/* Evidence Key-Values & Event Indicators */}
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                Extracted Event Indicators & Matched Signatures
              </h2>
              <span className="text-[10px] font-mono text-[var(--fg-muted)]">
                {selectedIncident.evidences?.length || 0} SIGNALS RECORDED
              </span>
            </div>

            {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {selectedIncident.evidences.map((ev, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col justify-between font-mono"
                  >
                    <span className="text-[10px] uppercase font-bold text-[var(--fg-muted)] tracking-wider">
                      {ev.key.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs text-[var(--fg-primary)] mt-1 break-all font-semibold">
                      {ev.value}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-[var(--fg-muted)] font-mono py-4 text-center">
                No hostile exploitation patterns or anomalous volumetric floods detected.
              </p>
            )}
          </div>

          {/* Recommended Countermeasures */}
          {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
            <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                  Recommended Incident Mitigations
                </h2>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">FIREWALL & ACCESS RULES</span>
              </div>

              <ul className="flex flex-col gap-2 font-mono text-xs">
                {selectedIncident.remediations.map((rem, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-[var(--fg-secondary)]">
                    <CheckCircle2 className="h-4 w-4 text-[var(--accent-base)] shrink-0 mt-0.5" />
                    <span>{rem}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Actions & ML Feedback */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <button
              type="button"
              onClick={() => onDownloadReport(selectedIncident.id)}
              className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition cursor-pointer"
            >
              <FileDown className="h-3.5 w-3.5" />
              <span>Export Log Analysis PDF</span>
            </button>

            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-[10px] text-[var(--fg-muted)] uppercase">Model Feedback:</span>
              <button
                type="button"
                onClick={() => onTrainML(selectedIncident.id, "PHISHING")}
                className="px-2.5 py-1 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition cursor-pointer"
              >
                Mark Hostile
              </button>
              <button
                type="button"
                onClick={() => onTrainML(selectedIncident.id, "SAFE")}
                className="px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition cursor-pointer"
              >
                Mark Benign
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { 
  Link as LinkIcon, 
  Search, 
  RefreshCw, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  FileDown, 
  BrainCircuit, 
  Copy, 
  Check, 
  ExternalLink,
  Info,
  CheckCircle2
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

interface UrlAnalysisWorkspaceProps {
  urlInput: string;
  setUrlInput: (val: string) => void;
  urlScanning: boolean;
  onStartScan: (e?: React.FormEvent, directUrl?: string) => Promise<void>;
  selectedIncident: IncidentDetail | null;
  onDownloadReport: (id: string) => void;
  onTrainML: (id: string, label: string) => void;
}

export function UrlAnalysisWorkspace({
  urlInput,
  setUrlInput,
  urlScanning,
  onStartScan,
  selectedIncident,
  onDownloadReport,
  onTrainML,
}: UrlAnalysisWorkspaceProps) {
  const [copied, setCopied] = useState(false);

  const samplePresets = [
    { label: "google.com", url: "https://google.com" },
    { label: "microsoft.com", url: "https://microsoft.com" },
    { label: "paypa1-spoof", url: "http://paypa1-secure-login.example.com/login" }
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const hasResult = selectedIncident && selectedIncident.vector_type === "URL" && !urlScanning;

  return (
    <div className="flex flex-col gap-6" data-od-id="url-analysis-workspace">
      {/* 1. WORKSPACE HEADER & SCOPE */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Vector // URL Reputation
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">HEURISTIC + ML PIPELINE</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            URL & Domain Reputation Forensics
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Audit domains, links, and subdomains for typosquatting, brand impersonation, punycode spoofing, and phishing indicators.
          </p>
        </div>

        {/* Presets */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[10px] text-[var(--fg-muted)] font-mono uppercase mr-1">Presets:</span>
          {samplePresets.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => {
                setUrlInput(preset.url);
                onStartScan(undefined, preset.url);
              }}
              className="px-2.5 py-1 bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] rounded text-[11px] font-mono text-[var(--fg-secondary)] hover:text-[var(--fg-primary)] transition cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* 2. URL INPUT CARD */}
      <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <form onSubmit={(e) => onStartScan(e)} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--fg-muted)] font-mono text-xs select-none">
              https://
            </div>
            <input
              type="text"
              placeholder="Enter domain or target link (e.g. secure-login.account-update.com/verify)..."
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              required
              className="w-full bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded pl-20 pr-4 py-2.5 text-xs text-[var(--fg-primary)] placeholder-[var(--fg-muted)] focus:outline-none focus:border-[var(--border-focus)] font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={urlScanning}
            className="px-5 py-2.5 bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white font-semibold text-xs rounded transition shadow-sm flex items-center justify-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
            data-od-id="start-url-scan-btn"
          >
            {urlScanning ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                <span>Auditing Target...</span>
              </>
            ) : (
              <>
                <Search className="h-3.5 w-3.5" />
                <span>Start URL Audit</span>
              </>
            )}
          </button>
        </form>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] text-[var(--fg-muted)] font-mono pt-3 mt-3 border-t border-[var(--border-subtle)]">
          <span className="flex items-center gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-[var(--state-safe-fg)]" />
            <span>Passive Inspection: No intrusive requests sent to destination server.</span>
          </span>
          <span>ENGINES: LEVENSHTEIN + NAIVE BAYES + RFC 3986 PARSER</span>
        </div>
      </div>

      {/* 3. SCANNING IN-PROGRESS STATE */}
      {urlScanning && (
        <div className="p-6 rounded-lg bg-[var(--bg-surface)] border border-[var(--state-info-border)] flex items-center gap-4 animate-pulse">
          <RefreshCw className="h-6 w-6 text-[var(--state-info-fg)] animate-spin shrink-0" />
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-bold text-[var(--fg-primary)] font-mono">
              Running Multi-Vector URL Forensics Pipeline...
            </span>
            <span className="text-[11px] text-[var(--fg-muted)] font-mono">
              Extracting domain tokens, verifying brand distance against protected targets, and calculating Laplace-smoothed Naive Bayes inference.
            </span>
          </div>
        </div>
      )}

      {/* 4. REAL FORENSIC RESULT VIEW */}
      {hasResult && selectedIncident && (
        <div className="flex flex-col gap-5">
          {/* Main Verdict Banner */}
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                Evaluated Target
              </span>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold font-mono text-[var(--fg-primary)] break-all">
                  {selectedIncident.target_input}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy(selectedIncident.target_input)}
                  className="p-1 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-elevated)] transition cursor-pointer"
                  title="Copy target URL"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-[var(--state-safe-fg)]" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
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

          {/* Evidence Key-Values & Technical Findings */}
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                Technical Evidence & Feature Extraction
              </h2>
              <span className="text-[10px] font-mono text-[var(--fg-muted)]">
                {selectedIncident.evidences?.length || 0} INDICATORS RECORDED
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
                No specific threat markers extracted. URL matches baseline legitimate distribution.
              </p>
            )}
          </div>

          {/* Recommended Countermeasures */}
          {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
            <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-[var(--border-subtle)]">
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                  Recommended Operational Remediations
                </h2>
                <span className="text-[10px] font-mono text-[var(--fg-muted)]">SOC WORKFLOW</span>
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

          {/* Actions & ML Human Feedback */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onDownloadReport(selectedIncident.id)}
                className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition cursor-pointer"
                title="Download native ReportLab PDF incident document"
              >
                <FileDown className="h-3.5 w-3.5" />
                <span>Export PDF Report</span>
              </button>
            </div>

            {/* Human in the loop feedback */}
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-[10px] text-[var(--fg-muted)] uppercase">Model Feedback:</span>
              <button
                type="button"
                onClick={() => onTrainML(selectedIncident.id, "PHISHING")}
                className="px-2.5 py-1 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition cursor-pointer"
                title="Reinforce Naive Bayes model: mark as PHISHING"
              >
                Mark Phishing
              </button>
              <button
                type="button"
                onClick={() => onTrainML(selectedIncident.id, "SAFE")}
                className="px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition cursor-pointer"
                title="Reinforce Naive Bayes model: mark as SAFE"
              >
                Mark Legitimate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

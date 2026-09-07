"use client";

import React, { useState } from "react";
import { 
  FileDown, 
  FileText, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Clock, 
  Layers, 
  Check, 
  Copy, 
  ExternalLink,
  Printer,
  ChevronRight,
  Database
} from "lucide-react";
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

interface ReportsWorkspaceProps {
  incidents: Incident[];
  selectedReportId: string | null;
  onSelectReportId: (id: string) => void;
  onDownloadReport: (id: string) => void;
  onDownloadGlobalReport: () => void;
  selectedIncidentDetail: any | null;
}

export function ReportsWorkspace({
  incidents,
  selectedReportId,
  onSelectReportId,
  onDownloadReport,
  onDownloadGlobalReport,
  selectedIncidentDetail,
}: ReportsWorkspaceProps) {
  const [copied, setCopied] = useState(false);

  const activeIncident = incidents.find(i => i.id === selectedReportId) || incidents[0] || null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col gap-6" data-od-id="reports-workspace">
      {/* 1. HEADER & GLOBAL EXPORT CONTROLS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Compliance // Investigation Records
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">REPORTLAB PDF ENGINE</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Forensic Intelligence & Audit Reports
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Export legally-admissible incident records, executive threat summaries, and containment action audits.
          </p>
        </div>

        {/* Global Executive PDF Trigger */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onDownloadGlobalReport}
            className="px-3.5 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition flex items-center gap-2 shadow-sm"
          >
            <FileDown className="h-4 w-4" />
            <span>Executive SOC Summary (PDF)</span>
          </button>
        </div>
      </div>

      {/* 2. REPORT SELECTOR & INCIDENT RECORD VIEWER */}
      {incidents.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Left Column: Report Ledger Selector */}
          <div className="rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
                Incident Audit Ledger
              </span>
              <span className="text-[10px] font-mono text-[var(--fg-muted)]">
                {incidents.length} AUDITED
              </span>
            </div>

            <div className="flex flex-col gap-1.5 max-h-[600px] overflow-y-auto pr-1">
              {incidents.map((inc) => {
                const isSelected = (activeIncident && activeIncident.id === inc.id);
                return (
                  <button
                    key={inc.id}
                    type="button"
                    onClick={() => onSelectReportId(inc.id)}
                    className={`w-full text-left p-3 rounded border text-xs font-mono transition flex flex-col gap-1.5 ${
                      isSelected
                        ? "bg-[var(--accent-surface)] border-[var(--accent-base)] text-[var(--fg-primary)]"
                        : "bg-[var(--bg-elevated)] border-[var(--border-subtle)] text-[var(--fg-secondary)] hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[11px] text-[var(--fg-primary)]">
                        REP-{inc.id.substring(0, 8).toUpperCase()}
                      </span>
                      <StatusBadge status={inc.status} size="sm" />
                    </div>
                    <p className="text-[11px] text-[var(--fg-code)] truncate" title={inc.target_input}>
                      {inc.target_input}
                    </p>
                    <div className="flex items-center justify-between text-[10px] text-[var(--fg-muted)] pt-1 border-t border-[var(--border-subtle)]">
                      <span>{inc.vector_type}</span>
                      <span>{inc.timestamp.substring(0, 10)}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Full Forensic Investigation Record (2 Cols) */}
          {activeIncident && (
            <div className="lg:col-span-2 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] p-6 flex flex-col gap-6 shadow-sm">
              
              {/* Document Masthead */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[10px] font-mono text-[var(--fg-muted)]">
                      CLASSIFICATION RECORD // CONFIDENTIAL
                    </span>
                    <span className="text-xs font-mono text-[var(--fg-muted)]">
                      AUDIT TIER 1
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-[var(--fg-primary)] font-mono">
                    Incident Forensic Triage Record #REP-{activeIncident.id.substring(0, 8).toUpperCase()}
                  </h2>
                  <p className="text-xs text-[var(--fg-secondary)] mt-1 font-mono">
                    System-generated security audit record via ReportLab backend daemon.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => onDownloadReport(activeIncident.id)}
                  className="px-3.5 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition flex items-center gap-2 shrink-0 shadow-sm"
                >
                  <FileDown className="h-4 w-4" />
                  <span>Download Incident PDF</span>
                </button>
              </div>

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] font-mono text-xs">
                <div>
                  <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-0.5">Classification</span>
                  <StatusBadge status={activeIncident.status} size="sm" />
                </div>
                <div>
                  <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-0.5">Threat Severity</span>
                  <span className="font-bold text-[var(--fg-primary)]">{activeIncident.severity}</span>
                </div>
                <div>
                  <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-0.5">Confidence Score</span>
                  <span className="font-bold text-[var(--fg-primary)]">{activeIncident.threat_score} / 100</span>
                </div>
                <div>
                  <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-0.5">Ingest Vector</span>
                  <span className="font-bold text-[var(--fg-primary)]">{activeIncident.vector_type}</span>
                </div>
              </div>

              {/* Artifact Payload Section */}
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
                  Subject Target Artifact Payload
                </span>
                <div className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] font-mono text-xs text-[var(--fg-code)] break-all select-all flex items-center justify-between gap-3">
                  <span>{activeIncident.target_input}</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(activeIncident.target_input)}
                    className="text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition shrink-0 p-1"
                    title="Copy payload"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>

              {/* Evidence / Findings Table */}
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
                  Forensic Evidence & Indicators of Compromise
                </span>
                {selectedIncidentDetail?.evidences && selectedIncidentDetail.evidences.length > 0 ? (
                  <div className="rounded border border-[var(--border-subtle)] overflow-hidden font-mono text-xs">
                    <table className="w-full text-left">
                      <thead className="bg-[var(--bg-elevated)] border-b border-[var(--border-subtle)] text-[10px] uppercase text-[var(--fg-muted)]">
                        <tr>
                          <th className="p-2.5">Indicator Key</th>
                          <th className="p-2.5">Detected Value / Payload</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--border-subtle)]">
                        {selectedIncidentDetail.evidences.map((ev: any, idx: number) => (
                          <tr key={idx} className="hover:bg-[var(--bg-hover)]">
                            <td className="p-2.5 font-bold text-[var(--accent-base)] uppercase text-[11px] whitespace-nowrap">
                              {ev.key}
                            </td>
                            <td className="p-2.5 text-[var(--fg-code)] break-all select-all">
                              {ev.value}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--fg-muted)] font-mono">
                    Artifact evaluated authentic. Zero synthetic or malicious compromise indicators mapped.
                  </div>
                )}
              </div>

              {/* Remediation & Containment */}
              {selectedIncidentDetail?.remediations && selectedIncidentDetail.remediations.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--fg-primary)]">
                    Prescribed Containment Directives
                  </span>
                  <ul className="flex flex-col gap-1.5 font-mono text-xs">
                    {selectedIncidentDetail.remediations.map((rem: any, idx: number) => (
                      <li key={idx} className="p-2.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[var(--fg-secondary)] flex items-start gap-2">
                        <span className="text-[var(--accent-base)] font-bold">[{idx + 1}]</span>
                        <span>{typeof rem === "string" ? rem : rem.description}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Verification & Attestation Footer */}
              <div className="pt-4 border-t border-[var(--border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-[10px] font-mono text-[var(--fg-muted)]">
                <div className="flex items-center gap-1.5">
                  <Database className="h-3.5 w-3.5 text-[var(--accent-base)]" />
                  <span>Verified Database Record // PostgreSQL Immutable Schema</span>
                </div>
                <span>Incident Timestamp: {activeIncident.timestamp}</span>
              </div>

            </div>
          )}

        </div>
      ) : (
        <div className="p-12 text-center rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] font-mono text-xs text-[var(--fg-muted)]">
          No incident investigations recorded in database yet.
        </div>
      )}
    </div>
  );
}

"use client";

import React, { useState, useMemo } from "react";
import { 
  Search, 
  Filter, 
  Trash2, 
  FileDown, 
  BrainCircuit, 
  ChevronDown, 
  ExternalLink,
  Shield,
  AlertCircle,
  RefreshCw,
  SlidersHorizontal,
  Check
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

interface ThreatQueueTableProps {
  incidents: Incident[];
  selectedId: string | null;
  onSelectIncident: (id: string) => void;
  onDeleteIncident: (id: string) => void;
  onTrainML: (id: string, label: string) => void;
  onDownloadReport: (id: string) => void;
  userEmail: string | null;
  loadingList?: boolean;
}

export function ThreatQueueTable({
  incidents,
  selectedId,
  onSelectIncident,
  onDeleteIncident,
  onTrainML,
  onDownloadReport,
  userEmail,
  loadingList = false,
}: ThreatQueueTableProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [vectorFilter, setVectorFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [activeDropdownId, setActiveDropdownId] = useState<string | null>(null);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchVector = vectorFilter === "ALL" || inc.vector_type.toUpperCase() === vectorFilter.toUpperCase();
      const matchStatus = statusFilter === "ALL" || inc.status.toUpperCase() === statusFilter.toUpperCase();
      const matchSeverity = severityFilter === "ALL" || inc.severity.toUpperCase() === severityFilter.toUpperCase();
      const q = searchQuery.toLowerCase().trim();
      const matchSearch = !q || 
        inc.target_input.toLowerCase().includes(q) ||
        inc.id.toLowerCase().includes(q) ||
        inc.status.toLowerCase().includes(q) ||
        inc.vector_type.toLowerCase().includes(q);
      return matchVector && matchStatus && matchSeverity && matchSearch;
    });
  }, [incidents, vectorFilter, statusFilter, severityFilter, searchQuery]);

  return (
    <div className="flex flex-col gap-5" data-od-id="threat-queue-table">
      {/* 1. HEADER & CONTROLS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Queue Management // Triage
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">
              {filteredIncidents.length} OF {incidents.length} RECORDED
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Active Threat Triage Queue
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Audit recorded compromise events, vector artifacts, threat classifications, and analyst action triggers.
          </p>
        </div>

        {/* Search & Filter Bar */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--fg-muted)]" />
            <input
              type="text"
              placeholder="Filter artifact or ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] focus:border-[var(--border-focus)] text-xs text-[var(--fg-primary)] placeholder:text-[var(--fg-muted)] outline-none font-mono w-44 sm:w-56"
            />
          </div>

          <select
            value={vectorFilter}
            onChange={(e) => setVectorFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs font-mono text-[var(--fg-primary)] outline-none cursor-pointer"
          >
            <option value="ALL">All Vectors</option>
            <option value="URL">URL</option>
            <option value="EMAIL">Email</option>
            <option value="LOG">Log / PCAP</option>
            <option value="DEEPFAKE">Deepfake</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs font-mono text-[var(--fg-primary)] outline-none cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="PHISHING">Phishing</option>
            <option value="DEEPFAKE">Deepfake</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="SAFE">Safe</option>
            <option value="PENDING">Pending</option>
          </select>
        </div>
      </div>

      {/* 2. TABLE CONTAINER */}
      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-sans">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--fg-muted)] font-mono text-[10px] uppercase tracking-wider">
                <th className="py-3 px-4 font-semibold">Incident Ref</th>
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Vector</th>
                <th className="py-3 px-4 font-semibold">Artifact Target Payload</th>
                <th className="py-3 px-4 font-semibold">Classification</th>
                <th className="py-3 px-4 font-semibold">Threat Score</th>
                <th className="py-3 px-4 font-semibold text-right">Analyst Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)] font-mono text-xs">
              {filteredIncidents.length > 0 ? (
                filteredIncidents.map((inc) => {
                  const isSelected = selectedId === inc.id;
                  return (
                    <tr
                      key={inc.id}
                      onClick={() => onSelectIncident(inc.id)}
                      className={`hover:bg-[var(--bg-hover)] transition-colors cursor-pointer ${
                        isSelected ? "bg-[var(--accent-surface)] border-l-2 border-[var(--accent-base)]" : ""
                      }`}
                    >
                      <td className="py-3 px-4 font-semibold text-[var(--fg-primary)]">
                        {inc.id.substring(0, 8)}...
                      </td>
                      <td className="py-3 px-4 text-[var(--fg-secondary)] text-[11px]">
                        {inc.timestamp.substring(0, 16).replace("T", " ")}
                      </td>
                      <td className="py-3 px-4 text-[var(--fg-primary)] font-medium">
                        <span className="px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[10px]">
                          {inc.vector_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[var(--fg-code)] max-w-xs truncate" title={inc.target_input}>
                        {inc.target_input}
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={inc.status} size="sm" />
                      </td>
                      <td className="py-3 px-4">
                        <div className="w-24">
                          <ThreatMeter score={inc.threat_score} size="sm" />
                        </div>
                      </td>
                      <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          {/* ML Retrain dropdown */}
                          <div className="relative">
                            <button
                              type="button"
                              onClick={() => setActiveDropdownId(activeDropdownId === inc.id ? null : inc.id)}
                              className="px-2 py-1 rounded bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[10px] font-mono font-medium text-[var(--fg-secondary)] hover:text-[var(--fg-primary)] border border-[var(--border-subtle)] transition flex items-center gap-1"
                              title="Retrain Machine Learning Model"
                            >
                              <BrainCircuit className="h-3 w-3 text-[var(--accent-base)]" />
                              <span>Train</span>
                              <ChevronDown className="h-2.5 w-2.5" />
                            </button>

                            {activeDropdownId === inc.id && (
                              <div className="absolute right-0 top-full mt-1 w-32 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] shadow-xl z-50 py-1 font-mono text-[10px] animate-in fade-in duration-150">
                                {(["PHISHING", "DEEPFAKE", "SUSPICIOUS", "SAFE"] as const).map((label) => (
                                  <button
                                    key={label}
                                    type="button"
                                    onClick={() => {
                                      onTrainML(inc.id, label);
                                      setActiveDropdownId(null);
                                    }}
                                    className="w-full text-left px-3 py-1.5 hover:bg-[var(--bg-hover)] text-[var(--fg-secondary)] hover:text-[var(--fg-primary)] transition"
                                  >
                                    Classify as {label}
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* PDF report export */}
                          <button
                            type="button"
                            onClick={() => onDownloadReport(inc.id)}
                            className="p-1 rounded bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-muted)] hover:text-[var(--fg-primary)] border border-[var(--border-subtle)] transition"
                            title="Download ReportLab PDF"
                          >
                            <FileDown className="h-3.5 w-3.5" />
                          </button>

                          {/* Delete */}
                          <button
                            type="button"
                            onClick={() => onDeleteIncident(inc.id)}
                            className="p-1 rounded bg-[var(--bg-elevated)] hover:bg-rose-500/10 text-[var(--fg-muted)] hover:text-rose-400 border border-[var(--border-subtle)] transition"
                            title="Purge incident record"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 px-4 text-center text-[var(--fg-muted)]">
                    <AlertCircle className="h-6 w-6 mx-auto mb-2 opacity-50" />
                    <p className="text-xs font-mono">No incidents match the active filter criteria.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

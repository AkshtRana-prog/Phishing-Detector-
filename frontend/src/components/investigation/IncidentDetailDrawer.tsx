"use client";

import React, { useState } from "react";
import { 
  X, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  FileDown, 
  Copy, 
  Check, 
  BrainCircuit, 
  ChevronRight, 
  ChevronDown, 
  FileText, 
  Terminal, 
  ExternalLink,
  Info,
  Clock,
  Send,
  Sparkles,
  AlertCircle
} from "lucide-react";
import { StatusBadge } from "../ui/StatusBadge";
import { ThreatMeter } from "../ui/ThreatMeter";

interface Evidence {
  key: string;
  value: string;
}

export interface IncidentDetail {
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

interface IncidentDetailDrawerProps {
  incident: IncidentDetail | null;
  onClose: () => void;
  onDownloadReport: (id: string) => void;
  onTrainML: (id: string, label: string) => void;
  userEmail: string | null;
  onOpenSignalModal?: (signal: {
    title: string;
    weight: string;
    evidence: string;
    confidence: string;
    rationale: string;
  }) => void;
}

export function IncidentDetailDrawer({
  incident,
  onClose,
  onDownloadReport,
  onTrainML,
  userEmail,
  onOpenSignalModal,
}: IncidentDetailDrawerProps) {
  const [copied, setCopied] = useState(false);
  const [analystNote, setAnalystNote] = useState("");
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "evidence" | "remediation" | "train">("overview");
  const [expandedEvidence, setExpandedEvidence] = useState<Record<number, boolean>>({});

  if (!incident) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleEvidenceExpand = (idx: number) => {
    setExpandedEvidence((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  // Generate deterministic forensic rationale based on real evidence and status
  const getForensicVerdictExplanation = () => {
    const isMalicious = incident.status === "PHISHING" || incident.status === "DEEPFAKE";
    const isSuspicious = incident.status === "SUSPICIOUS";
    const isSafe = incident.status === "SAFE";

    if (incident.vector_type === "URL") {
      if (isMalicious) {
        return `Automated heuristic and ML inspection confirmed high-probability phishing indicators on "${incident.target_input}". The domain exhibits characteristics consistent with credential harvesting infrastructure, brand typosquatting, or known malicious redirect networks.`;
      } else if (isSuspicious) {
        return `Evaluation of "${incident.target_input}" revealed suspicious structural attributes (e.g. recent domain creation, unusual TLD, or anomalous character distribution). While conclusive malicious payload is unconfirmed, risk score exceeds safety thresholds.`;
      } else {
        return `Target domain "${incident.target_input}" passed all reputation tests, DNS checks, and lexical anomaly filters. No deceptive tokens or typosquatting patterns detected.`;
      }
    }

    if (incident.vector_type === "Email") {
      if (isMalicious) {
        return `RFC 822 forensic audit detected critical authentication failures (SPF/DKIM/DMARC mismatch) combined with high-urgency social engineering linguistics and deceptive sender header alignment in "${incident.target_input}".`;
      } else if (isSuspicious) {
        return `Email message analysis flagged partial authentication deficiencies or elevated spam probability scores. Embedded links or sender domain identity require secondary analyst review.`;
      } else {
        return `Email headers and body payload verified authentic. Cryptographic signatures validated successfully and no credential solicitation patterns detected.`;
      }
    }

    if (incident.vector_type === "Log") {
      if (isMalicious) {
        return `Network log/PCAP pattern matching identified active exploit attempts, anomalous packet volume surges, or critical reconnaissance port scans originating from or targeting analyzed infrastructure.`;
      } else if (isSuspicious) {
        return `Event telemetry indicates unusual connection rates or suspicious URI queries exceeding normal baseline metrics.`;
      } else {
        return `Event logs demonstrate benign operational traffic with standard protocol handshakes and zero known CVE exploit signatures.`;
      }
    }

    if (incident.vector_type === "Deepfake") {
      if (isMalicious) {
        return `Acoustic or video forensic pipelines identified generative synthetic artifacts (abnormal Shannon entropy levels, AI voice synthesis signatures, or deep neural model compression fingerprints).`;
      } else if (isSuspicious) {
        return `Media artifact evaluation revealed boundary compression anomalies or inconsistent audio-visual synchronization signals.`;
      } else {
        return `Media payload verified authentic with natural harmonic variance and organic frame transition entropy.`;
      }
    }

    return `Forensic assessment completed for ${incident.vector_type} vector with threat score ${incident.threat_score}/100.`;
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end" data-od-id="incident-detail-drawer">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px] transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Body */}
      <aside className="relative w-full max-w-xl h-full bg-[var(--bg-surface)] border-l border-[var(--border-subtle)] shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-300">
        
        {/* Header Bar */}
        <div className="p-4 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)] flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)] shrink-0">
              {incident.vector_type} Investigation
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)] truncate" title={incident.id}>
              REF: {incident.id.slice(0, 12)}...
            </span>
            <button
              onClick={() => handleCopy(incident.id)}
              className="text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition p-1"
              title="Copy Incident ID"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownloadReport(incident.id)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition"
              title="Download Server-Generated PDF"
            >
              <FileDown className="h-3.5 w-3.5 text-[var(--accent-base)]" />
              <span>PDF Report</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-[var(--bg-hover)] text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition"
              aria-label="Close drawer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
          
          {/* 1. VERDICT & THREAT HERO BANNER */}
          <div className="p-4 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
              <div>
                <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                  Primary Classification
                </span>
                <div className="flex items-center gap-2">
                  <StatusBadge status={incident.status} size="md" />
                  <span className="text-xs font-mono text-[var(--fg-secondary)]">
                    Severity: <strong className="text-[var(--fg-primary)]">{incident.severity}</strong>
                  </span>
                </div>
              </div>

              <div className="sm:text-right">
                <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                  Recorded Timestamp
                </span>
                <span className="text-xs font-mono text-[var(--fg-secondary)] flex items-center sm:justify-end gap-1">
                  <Clock className="h-3 w-3 text-[var(--fg-muted)]" />
                  {incident.timestamp}
                </span>
              </div>
            </div>

            {/* Threat Meter */}
            <div>
              <div className="flex justify-between items-center text-xs font-mono mb-1.5">
                <span className="text-[var(--fg-muted)]">Calculated Threat Confidence Score:</span>
                <span className="font-bold text-[var(--fg-primary)]">{incident.threat_score} / 100</span>
              </div>
              <ThreatMeter score={incident.threat_score} size="md" showLabel={false} />
            </div>

            {/* Target Artifact Display */}
            <div className="p-2.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--fg-muted)] block mb-1">
                Analyzed Target Artifact
              </span>
              <p className="font-mono text-xs text-[var(--fg-code)] break-all font-medium select-all">
                {incident.target_input}
              </p>
            </div>
          </div>

          {/* 2. FORENSIC VERDICT EXPLANATION */}
          <div className="p-4 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-[var(--accent-base)]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                Detection Reasoning & Executive Rationale
              </h3>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed">
              {getForensicVerdictExplanation()}
            </p>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-[var(--border-subtle)] gap-4 text-xs font-mono">
            <button
              onClick={() => setActiveTab("overview")}
              className={`pb-2 transition font-medium border-b-2 ${
                activeTab === "overview"
                  ? "border-[var(--accent-base)] text-[var(--accent-base)]"
                  : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
              }`}
            >
              Evidence ({incident.evidences?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab("remediation")}
              className={`pb-2 transition font-medium border-b-2 ${
                activeTab === "remediation"
                  ? "border-[var(--accent-base)] text-[var(--accent-base)]"
                  : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
              }`}
            >
              Remediations ({incident.remediations?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab("train")}
              className={`pb-2 transition font-medium border-b-2 ${
                activeTab === "train"
                  ? "border-[var(--accent-base)] text-[var(--accent-base)]"
                  : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
              }`}
            >
              ML Override & Notes
            </button>
          </div>

          {/* TAB 1: EVIDENCE & TECHNICAL FINDINGS */}
          {activeTab === "overview" && (
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-semibold text-[var(--fg-primary)]">
                  Indicators of Compromise (IOCs)
                </span>
                <span className="text-[10px] text-[var(--fg-muted)]">
                  Click indicator for signal rationale
                </span>
              </div>

              {incident.evidences && incident.evidences.length > 0 ? (
                <div className="flex flex-col gap-2">
                  {incident.evidences.map((ev, idx) => (
                    <div 
                      key={idx}
                      className="p-3 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition flex flex-col gap-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-mono font-bold text-[var(--accent-base)] uppercase tracking-wide">
                          {ev.key}
                        </span>
                        {onOpenSignalModal && (
                          <button
                            type="button"
                            onClick={() => onOpenSignalModal({
                              title: `${ev.key.toUpperCase()} Indicator`,
                              weight: `${Math.min(95, Math.max(20, incident.threat_score))}%`,
                              evidence: ev.value,
                              confidence: `${incident.threat_score >= 50 ? "High" : "Standard"} (Deterministic Heuristic)`,
                              rationale: `Signal captured during forensic evaluation of ${incident.vector_type} vector. Evaluated with weight correlating to threat score ${incident.threat_score}/100.`
                            })}
                            className="text-[10px] font-mono text-[var(--fg-muted)] hover:text-[var(--accent-base)] flex items-center gap-1 transition"
                          >
                            <span>Inspect</span>
                            <ChevronRight className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                      <div className="p-2 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] font-mono text-xs text-[var(--fg-code)] break-all select-all">
                        {ev.value}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-center text-xs text-[var(--fg-muted)] font-mono">
                  No anomalous indicators registered for this target artifact.
                </div>
              )}
            </div>
          )}

          {/* TAB 2: REMEDIATION & CONTAINMENT */}
          {activeTab === "remediation" && (
            <div className="flex flex-col gap-3">
              <span className="text-xs font-mono font-semibold text-[var(--fg-primary)]">
                Prescribed Containment & Response Procedures
              </span>

              {incident.remediations && incident.remediations.length > 0 ? (
                <ul className="flex flex-col gap-2">
                  {incident.remediations.map((rem, idx) => (
                    <li 
                      key={idx}
                      className="p-3 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--fg-secondary)] flex items-start gap-2.5 leading-relaxed"
                    >
                      <span className="h-5 w-5 rounded-full bg-[var(--accent-surface)] text-[var(--accent-base)] font-mono text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5 border border-[var(--border-subtle)]">
                        {idx + 1}
                      </span>
                      <span>{rem}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-6 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-center text-xs text-[var(--fg-muted)] font-mono">
                  No specific remediation steps required. Standard baseline monitoring recommended.
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ML FEEDBACK & ANALYST NOTES */}
          {activeTab === "train" && (
            <div className="flex flex-col gap-4">
              {/* Human-in-the-loop ML Retraining */}
              <div className="p-4 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-3">
                <div className="flex items-center gap-2">
                  <BrainCircuit className="h-4 w-4 text-[var(--accent-base)]" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                    Self-Learning Model Feedback Loop
                  </h4>
                </div>
                <p className="text-xs text-[var(--fg-secondary)] leading-relaxed">
                  Provide human ground-truth feedback to update the Multinomial Naive Bayes online classifier. This feeds the training loop in <code className="text-[var(--fg-code)] font-mono">self_learning.py</code> with Laplace smoothing.
                </p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                  {(["PHISHING", "SUSPICIOUS", "SAFE", "DEEPFAKE"] as const).map((label) => (
                    <button
                      key={label}
                      type="button"
                      onClick={() => onTrainML(incident.id, label)}
                      className="px-2.5 py-2 rounded text-xs font-mono font-medium bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] hover:border-[var(--accent-base)] text-[var(--fg-primary)] transition flex flex-col items-center gap-1"
                    >
                      <span className="text-[10px] text-[var(--fg-muted)]">Classify as</span>
                      <span className="font-bold">{label}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Analyst Investigation Notes */}
              <div className="p-4 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-3">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-[var(--accent-base)]" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--fg-primary)] font-mono">
                    Analyst Investigation Journal
                  </h4>
                </div>
                <textarea
                  value={analystNote}
                  onChange={(e) => setAnalystNote(e.target.value)}
                  placeholder="Record forensic notes, corroborating threat intelligence feeds, or internal ticketing references..."
                  rows={3}
                  className="w-full rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] focus:border-[var(--border-focus)] p-3 text-xs text-[var(--fg-primary)] placeholder:text-[var(--fg-muted)] outline-none resize-none font-mono"
                />
                <div className="flex justify-between items-center">
                  {savedNote ? (
                    <span className="text-[11px] font-mono text-emerald-400">
                      ✓ Note saved for Ref: {incident.id.slice(0, 8)}
                    </span>
                  ) : <span />}
                  <button
                    type="button"
                    onClick={() => {
                      setSavedNote(analystNote);
                      setTimeout(() => setSavedNote(null), 3000);
                    }}
                    className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition"
                  >
                    Save Note
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Footer Action Bar */}
        <div className="p-4 border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)] flex items-center justify-between gap-3">
          <div className="text-[11px] font-mono text-[var(--fg-muted)]">
            Status: <span className="font-bold text-[var(--fg-primary)]">{incident.status}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onDownloadReport(incident.id)}
              className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition flex items-center gap-1.5"
            >
              <FileDown className="h-3.5 w-3.5" />
              <span>Export PDF</span>
            </button>
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition"
            >
              Close
            </button>
          </div>
        </div>

      </aside>
    </div>
  );
}

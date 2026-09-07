"use client";

import React, { useState } from "react";
import { 
  Search, 
  Link as LinkIcon, 
  Mail, 
  Terminal, 
  Video, 
  ArrowRight, 
  RefreshCw, 
  CheckCircle2, 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle,
  FileDown,
  Layers,
  Sparkles,
  ExternalLink
} from "lucide-react";
import { StatusBadge } from "../ui/StatusBadge";
import { ThreatMeter } from "../ui/ThreatMeter";

interface InvestigationWorkspaceProps {
  onNavigateTab: (tab: string) => void;
  // URL scan
  urlInput: string;
  setUrlInput: (val: string) => void;
  onStartURLScan: (e?: React.FormEvent, directUrl?: string) => Promise<void>;
  urlScanning: boolean;
  // EML scan
  emlFile: File | null;
  setEmlFile: (file: File | null) => void;
  onStartEMLScan: (e: React.FormEvent) => Promise<void>;
  emlScanning: boolean;
  // Log scan
  logFile: File | null;
  setLogFile: (file: File | null) => void;
  onStartLogScan: (e: React.FormEvent) => Promise<void>;
  logScanning: boolean;
  // Media scan
  mediaFile: File | null;
  setMediaFile: (file: File | null) => void;
  mediaType: "video" | "audio";
  setMediaType: (type: "video" | "audio") => void;
  onStartMediaScan: (e: React.FormEvent) => Promise<void>;
  mediaScanning: boolean;
  // Global scanning
  isScanningActive: boolean;
  timelineStep: number;
}

export function InvestigationWorkspace({
  onNavigateTab,
  urlInput,
  setUrlInput,
  onStartURLScan,
  urlScanning,
  emlFile,
  setEmlFile,
  onStartEMLScan,
  emlScanning,
  logFile,
  setLogFile,
  onStartLogScan,
  logScanning,
  mediaFile,
  setMediaFile,
  mediaType,
  setMediaType,
  onStartMediaScan,
  mediaScanning,
  isScanningActive,
  timelineStep,
}: InvestigationWorkspaceProps) {
  const [selectedVector, setSelectedVector] = useState<"ALL" | "URL" | "EMAIL" | "LOG" | "MEDIA">("ALL");

  const pipelineStages = [
    { step: 0, label: "Cryptographic signature & format verification" },
    { step: 1, label: "Host resolution & network infrastructure lookup" },
    { step: 2, label: "SSL / TLS / SPF / DKIM certificate verification" },
    { step: 3, label: "Threat intelligence database & typosquatting match" },
    { step: 4, label: "Entropy analysis & neural classifier inference" }
  ];

  return (
    <div className="flex flex-col gap-6" data-od-id="investigation-workspace">
      {/* 1. HEADER & SCOPE */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Operations // Multi-Vector Lab
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">ACTIVE TRIAGE CONSOLE</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Investigation Channels & Ingestion Lab
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Submit on-demand forensic workloads across web, email, log/PCAP, and acoustic/visual media vectors.
          </p>
        </div>

        {/* Vector Quick Jump */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            type="button"
            onClick={() => onNavigateTab("url_analysis")}
            className="px-2.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition flex items-center gap-1.5"
          >
            <LinkIcon className="h-3.5 w-3.5 text-[var(--accent-base)]" />
            <span>URL Lab</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab("email_analysis")}
            className="px-2.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition flex items-center gap-1.5"
          >
            <Mail className="h-3.5 w-3.5 text-purple-400" />
            <span>Email Lab</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab("log_analysis")}
            className="px-2.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition flex items-center gap-1.5"
          >
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span>Log Lab</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigateTab("media_analysis")}
            className="px-2.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition flex items-center gap-1.5"
          >
            <Video className="h-3.5 w-3.5 text-amber-400" />
            <span>Media Lab</span>
          </button>
        </div>
      </div>

      {/* 2. REAL-TIME PIPELINE PROGRESS (WHEN SCANNING) */}
      {(isScanningActive || urlScanning || emlScanning || logScanning || mediaScanning) && (
        <div className="p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-3 animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--accent-base)] flex items-center gap-2">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              Asynchronous Forensic Task Active (Celery Worker Queue)
            </span>
            <span className="text-[10px] font-mono text-[var(--fg-muted)]">HTTP 202 ACCEPTED</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2 pt-1">
            {pipelineStages.map((stage) => {
              const isDone = timelineStep > stage.step;
              const isCurrent = timelineStep === stage.step;
              return (
                <div 
                  key={stage.step}
                  className={`p-2.5 rounded border text-xs font-mono flex flex-col gap-1 transition-all ${
                    isDone 
                      ? "bg-[var(--bg-elevated)] border-emerald-500/30 text-[var(--fg-secondary)]"
                      : isCurrent
                        ? "bg-[var(--accent-surface)] border-[var(--accent-base)] text-[var(--fg-primary)]"
                        : "bg-[var(--bg-elevated)] border-[var(--border-subtle)] text-[var(--fg-muted)] opacity-60"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] uppercase tracking-wider font-bold">Stage 0{stage.step + 1}</span>
                    {isDone ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    ) : isCurrent ? (
                      <RefreshCw className="h-3.5 w-3.5 text-[var(--accent-base)] animate-spin" />
                    ) : (
                      <Clock className="h-3.5 w-3.5" />
                    )}
                  </div>
                  <span className="text-[11px] leading-tight mt-1">{stage.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. MULTI-VECTOR INGESTION CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* CARD 1: URL INGESTION */}
        <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between gap-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
                  <LinkIcon className="h-4 w-4" />
                </span>
                <h3 className="text-sm font-bold text-[var(--fg-primary)] font-mono">
                  URL & Domain Vector
                </h3>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab("url_analysis")}
                className="text-xs font-mono text-[var(--fg-muted)] hover:text-[var(--accent-base)] flex items-center gap-1 transition"
              >
                <span>Full Lab</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed mb-4">
              Inspect suspicious websites, shorteners, punycode spoofing, and lexical brand typosquatting.
            </p>
          </div>

          <form onSubmit={onStartURLScan} className="flex gap-2">
            <input
              type="url"
              placeholder="https://suspicious-domain.com/login"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              required
              disabled={urlScanning}
              className="flex-1 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] focus:border-[var(--border-focus)] px-3 py-2 text-xs text-[var(--fg-primary)] placeholder:text-[var(--fg-muted)] outline-none font-mono"
            />
            <button
              type="submit"
              disabled={urlScanning}
              className="px-4 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white transition shrink-0 flex items-center gap-1.5"
            >
              {urlScanning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
              <span>Scan URL</span>
            </button>
          </form>
        </div>

        {/* CARD 2: EML EMAIL INGESTION */}
        <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between gap-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <Mail className="h-4 w-4" />
                </span>
                <h3 className="text-sm font-bold text-[var(--fg-primary)] font-mono">
                  Email Forensics (EML)
                </h3>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab("email_analysis")}
                className="text-xs font-mono text-[var(--fg-muted)] hover:text-purple-400 flex items-center gap-1 transition"
              >
                <span>Full Lab</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed mb-4">
              Audit RFC 822 raw message files for SPF/DKIM/DMARC headers, sender display spoofing, and NLP phishing cues.
            </p>
          </div>

          <form onSubmit={onStartEMLScan} className="flex items-center gap-2">
            <input
              type="file"
              accept=".eml"
              onChange={(e) => setEmlFile(e.target.files?.[0] || null)}
              required
              disabled={emlScanning}
              className="flex-1 text-xs text-[var(--fg-secondary)] file:mr-2 file:py-1.5 file:px-2.5 file:rounded file:border-0 file:text-xs file:font-mono file:bg-[var(--bg-elevated)] file:text-[var(--fg-primary)] hover:file:bg-[var(--bg-hover)] cursor-pointer"
            />
            <button
              type="submit"
              disabled={emlScanning || !emlFile}
              className="px-4 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white transition shrink-0 flex items-center gap-1.5"
            >
              {emlScanning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
              <span>Audit EML</span>
            </button>
          </form>
        </div>

        {/* CARD 3: LOGS & PCAP INGESTION */}
        <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between gap-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Terminal className="h-4 w-4" />
                </span>
                <h3 className="text-sm font-bold text-[var(--fg-primary)] font-mono">
                  Log & PCAP Network Traffic
                </h3>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab("log_analysis")}
                className="text-xs font-mono text-[var(--fg-muted)] hover:text-emerald-400 flex items-center gap-1 transition"
              >
                <span>Full Lab</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed mb-4">
              Parse raw syslog lines or packet capture (PCAP/PCAPNG) frames for volumetric floods, port sweeps, and exploit patterns.
            </p>
          </div>

          <form onSubmit={onStartLogScan} className="flex items-center gap-2">
            <input
              type="file"
              accept=".log,.txt,.pcap,.pcapng"
              onChange={(e) => setLogFile(e.target.files?.[0] || null)}
              required
              disabled={logScanning}
              className="flex-1 text-xs text-[var(--fg-secondary)] file:mr-2 file:py-1.5 file:px-2.5 file:rounded file:border-0 file:text-xs file:font-mono file:bg-[var(--bg-elevated)] file:text-[var(--fg-primary)] hover:file:bg-[var(--bg-hover)] cursor-pointer"
            />
            <button
              type="submit"
              disabled={logScanning || !logFile}
              className="px-4 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white transition shrink-0 flex items-center gap-1.5"
            >
              {logScanning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
              <span>Audit Logs</span>
            </button>
          </form>
        </div>

        {/* CARD 4: DEEPFAKE MEDIA INGESTION */}
        <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col justify-between gap-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <Video className="h-4 w-4" />
                </span>
                <h3 className="text-sm font-bold text-[var(--fg-primary)] font-mono">
                  Deepfake & Voice Clone Forensics
                </h3>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab("media_analysis")}
                className="text-xs font-mono text-[var(--fg-muted)] hover:text-amber-400 flex items-center gap-1 transition"
              >
                <span>Full Lab</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed mb-4">
              Detect synthetic video artifacts, audio voice cloning (Shannon entropy & Wav2Vec), and neural generative container tags.
            </p>
          </div>

          <form onSubmit={onStartMediaScan} className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <div className="flex rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-0.5 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setMediaType("video")}
                  className={`px-2 py-0.5 rounded transition ${
                    mediaType === "video" ? "bg-[var(--accent-base)] text-white font-bold" : "text-[var(--fg-muted)]"
                  }`}
                >
                  Video
                </button>
                <button
                  type="button"
                  onClick={() => setMediaType("audio")}
                  className={`px-2 py-0.5 rounded transition ${
                    mediaType === "audio" ? "bg-[var(--accent-base)] text-white font-bold" : "text-[var(--fg-muted)]"
                  }`}
                >
                  Audio
                </button>
              </div>

              <input
                type="file"
                accept={mediaType === "video" ? ".mp4,.avi,.mov" : ".mp3,.wav"}
                onChange={(e) => setMediaFile(e.target.files?.[0] || null)}
                required
                disabled={mediaScanning}
                className="flex-1 text-xs text-[var(--fg-secondary)] file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:font-mono file:bg-[var(--bg-elevated)] file:text-[var(--fg-primary)] hover:file:bg-[var(--bg-hover)] cursor-pointer"
              />
              <button
                type="submit"
                disabled={mediaScanning || !mediaFile}
                className="px-3.5 py-1.5 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white transition shrink-0 flex items-center gap-1.5"
              >
                {mediaScanning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
                <span>Audit Media</span>
              </button>
            </div>
          </form>
        </div>

      </div>
    </div>
  );
}

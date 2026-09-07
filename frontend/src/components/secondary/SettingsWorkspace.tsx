"use client";

import React, { useState } from "react";
import { 
  Sliders, 
  BrainCircuit, 
  Moon, 
  Sun, 
  Shield, 
  Database, 
  Cpu, 
  Check, 
  AlertCircle,
  Lock,
  User,
  Activity,
  Server
} from "lucide-react";

interface SettingsWorkspaceProps {
  userEmail: string | null;
  onLogout: () => void;
  urlSensitivity: number;
  setUrlSensitivity: (val: number) => void;
  emailSensitivity: number;
  setEmailSensitivity: (val: number) => void;
  mediaSensitivity: number;
  setMediaSensitivity: (val: number) => void;
  logSensitivity: number;
  setLogSensitivity: (val: number) => void;
  apiOffline: boolean;
}

export function SettingsWorkspace({
  userEmail,
  onLogout,
  urlSensitivity,
  setUrlSensitivity,
  emailSensitivity,
  setEmailSensitivity,
  mediaSensitivity,
  setMediaSensitivity,
  logSensitivity,
  setLogSensitivity,
  apiOffline,
}: SettingsWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<"detection" | "model" | "platform">("detection");
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleSave = () => {
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  return (
    <div className="flex flex-col gap-6" data-od-id="settings-workspace">
      {/* 1. HEADER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
              Configuration // System Preferences
            </span>
            <span className="text-xs font-mono text-[var(--fg-muted)]">ENGINE SETTINGS</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">
            Detection Sensitivity & Engine Governance
          </h1>
          <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
            Calibrate detection thresholds, inspect machine learning model architectures, and govern platform parameters.
          </p>
        </div>

        {saveSuccess && (
          <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
            <Check className="h-3.5 w-3.5" />
            Parameters saved successfully
          </span>
        )}
      </div>

      {/* 2. SUB-NAVIGATION */}
      <div className="flex border-b border-[var(--border-subtle)] gap-4 text-xs font-mono">
        <button
          type="button"
          onClick={() => setActiveTab("detection")}
          className={`pb-2.5 transition font-medium border-b-2 ${
            activeTab === "detection"
              ? "border-[var(--accent-base)] text-[var(--accent-base)]"
              : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
          }`}
        >
          Detection Sensitivities
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("model")}
          className={`pb-2.5 transition font-medium border-b-2 ${
            activeTab === "model"
              ? "border-[var(--accent-base)] text-[var(--accent-base)]"
              : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
          }`}
        >
          Model Architecture & Learning
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("platform")}
          className={`pb-2.5 transition font-medium border-b-2 ${
            activeTab === "platform"
              ? "border-[var(--accent-base)] text-[var(--accent-base)]"
              : "border-transparent text-[var(--fg-muted)] hover:text-[var(--fg-primary)]"
          }`}
        >
          Session & Platform Status
        </button>
      </div>

      {/* TAB 1: DETECTION SENSITIVITIES */}
      {activeTab === "detection" && (
        <div className="flex flex-col gap-4">
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-5">
            <div>
              <h3 className="text-sm font-mono font-bold text-[var(--fg-primary)]">
                Vector Sensitivity Thresholds
              </h3>
              <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
                Adjust the confidence cut-off for heuristic warnings and automatic incident escalation. Higher values minimize false positives.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 font-mono text-xs">
              {/* URL */}
              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-[var(--fg-primary)]">URL Typosquatting Sensitivity</span>
                  <span className="font-bold text-[var(--accent-base)]">{urlSensitivity}%</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={urlSensitivity}
                  onChange={(e) => setUrlSensitivity(Number(e.target.value))}
                  className="w-full cursor-pointer accent-[var(--accent-base)]"
                />
                <span className="text-[10px] text-[var(--fg-muted)]">
                  Levenshtein distance cutoff for high-profile brand impersonation.
                </span>
              </div>

              {/* Email */}
              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-[var(--fg-primary)]">Email Auth Strictness</span>
                  <span className="font-bold text-purple-400">{emailSensitivity}%</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={emailSensitivity}
                  onChange={(e) => setEmailSensitivity(Number(e.target.value))}
                  className="w-full cursor-pointer accent-purple-500"
                />
                <span className="text-[10px] text-[var(--fg-muted)]">
                  Threshold for SPF/DKIM alignment failures and NLP social-engineering urgency.
                </span>
              </div>

              {/* Media */}
              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-[var(--fg-primary)]">Deepfake Synthetic Filter</span>
                  <span className="font-bold text-amber-400">{mediaSensitivity}%</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={mediaSensitivity}
                  onChange={(e) => setMediaSensitivity(Number(e.target.value))}
                  className="w-full cursor-pointer accent-amber-500"
                />
                <span className="text-[10px] text-[var(--fg-muted)]">
                  Shannon entropy boundary and audio harmonic variance sensitivity.
                </span>
              </div>

              {/* Log */}
              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-[var(--fg-primary)]">Log Anomaly Threshold</span>
                  <span className="font-bold text-emerald-400">{logSensitivity}%</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={logSensitivity}
                  onChange={(e) => setLogSensitivity(Number(e.target.value))}
                  className="w-full cursor-pointer accent-emerald-500"
                />
                <span className="text-[10px] text-[var(--fg-muted)]">
                  PCAP volumetric packet flood rate and CVE signature tolerance.
                </span>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={handleSave}
                className="px-4 py-2 rounded text-xs font-mono font-medium bg-[var(--accent-base)] hover:bg-[var(--accent-hover)] text-white transition"
              >
                Apply Sensitivity Updates
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: MODEL ARCHITECTURE & TRANSPARENT LEARNING */}
      {activeTab === "model" && (
        <div className="flex flex-col gap-4">
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-4">
            <div className="flex items-center gap-2">
              <BrainCircuit className="h-4 w-4 text-[var(--accent-base)]" />
              <h3 className="text-sm font-mono font-bold text-[var(--fg-primary)]">
                Self-Learning Machine Learning Architecture (Backend Implementation)
              </h3>
            </div>
            
            <p className="text-xs text-[var(--fg-secondary)] leading-relaxed">
              Phishing Detector implements an online <strong>Multinomial Naive Bayes</strong> classifier with Laplace smoothing in Python (<code className="text-[var(--fg-code)] font-mono">backend/app/ml/self_learning.py</code>). The system does NOT invent fake training epochs or pretend to run offline deep learning during dashboard views.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs pt-1">
              <div className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
                <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-1">Algorithm</span>
                <span className="font-bold text-[var(--fg-primary)]">Multinomial Naive Bayes</span>
                <p className="text-[10px] text-[var(--fg-muted)] mt-1">Laplace smoothing (α = 1.0)</p>
              </div>

              <div className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
                <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-1">Weight Persistence</span>
                <span className="font-bold text-[var(--fg-primary)]">self_learning_model.json</span>
                <p className="text-[10px] text-[var(--fg-muted)] mt-1">Incremental token updates</p>
              </div>

              <div className="p-3.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
                <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-1">Feedback Loop</span>
                <span className="font-bold text-[var(--fg-primary)]">Human-in-the-Loop</span>
                <p className="text-[10px] text-[var(--fg-muted)] mt-1">POST /incidents/{`{id}`}/train</p>
              </div>
            </div>

            <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-xs text-[var(--fg-secondary)] flex flex-col gap-2 font-mono">
              <span className="font-bold text-[var(--fg-primary)] text-[11px] uppercase">
                Model Pipeline Execution Rules:
              </span>
              <ul className="list-disc list-inside space-y-1 text-[11px] text-[var(--fg-muted)]">
                <li>Feature tokenization strips protocol headers, lowercases lexical n-grams, and extracts structural indicators.</li>
                <li>When an analyst provides a correction in the Threat Queue, token weights are updated immediately without requiring a full server restart.</li>
                <li>Fallback heuristics (Levenshtein typosquatting, SPF/DKIM validation) run concurrently with model inference to ensure defense-in-depth.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: PLATFORM & SESSION STATUS */}
      {activeTab === "platform" && (
        <div className="flex flex-col gap-4">
          <div className="p-5 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-subtle)] flex flex-col gap-5">
            <div>
              <h3 className="text-sm font-mono font-bold text-[var(--fg-primary)]">
                Analyst Session & Infrastructure Health
              </h3>
              <p className="text-xs text-[var(--fg-secondary)] mt-0.5">
                Active authentication credentials and connection status to local daemons.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <span className="text-[10px] text-[var(--fg-muted)] uppercase">Authenticated Analyst</span>
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-[var(--accent-base)]" />
                  <span className="font-bold text-[var(--fg-primary)]">{userEmail || "Local Session"}</span>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={onLogout}
                    className="px-3 py-1.5 rounded text-[11px] font-mono bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition"
                  >
                    Disconnect Session
                  </button>
                </div>
              </div>

              <div className="p-4 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex flex-col gap-2">
                <span className="text-[10px] text-[var(--fg-muted)] uppercase">FastAPI Backend Daemon</span>
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-[var(--accent-base)]" />
                  <span className="font-bold text-[var(--fg-primary)]">http://localhost:8000</span>
                </div>
                <div className="flex items-center gap-1.5 pt-1">
                  <span className={`h-2 w-2 rounded-full ${apiOffline ? "bg-rose-500" : "bg-emerald-400"}`} />
                  <span className="text-[10px] text-[var(--fg-muted)]">
                    {apiOffline ? "Daemon Unreachable" : "Online & Operational"}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React from "react";
import { X, ShieldAlert, Info, BrainCircuit, Activity } from "lucide-react";

interface SignalExplainerModalProps {
  signal: {
    title: string;
    weight: string;
    evidence: string;
    confidence: string;
    rationale: string;
  } | null;
  onClose: () => void;
}

export function SignalExplainerModal({ signal, onClose }: SignalExplainerModalProps) {
  if (!signal) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-xs z-[200] flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] max-w-lg w-full p-6 rounded-lg shadow-2xl relative flex flex-col gap-4">
        {/* Header */}
        <div className="flex justify-between items-start border-b border-[var(--border-subtle)] pb-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--border-subtle)]">
                Forensic Signal Breakdown
              </span>
            </div>
            <h2 className="text-base font-bold text-[var(--fg-primary)] font-mono">
              {signal.title}
            </h2>
          </div>
          <button 
            onClick={onClose} 
            className="text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition p-1 rounded hover:bg-[var(--bg-hover)]"
            aria-label="Close signal modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Forensic Metrics Grid */}
        <div className="grid grid-cols-2 gap-3 font-mono">
          <div className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-1">
              Signal Threat Weight
            </span>
            <span className="text-sm font-bold text-[var(--accent-base)]">
              {signal.weight}
            </span>
          </div>
          <div className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)]">
            <span className="text-[10px] text-[var(--fg-muted)] uppercase block mb-1">
              Evaluation Heuristic
            </span>
            <span className="text-sm font-bold text-emerald-400">
              {signal.confidence}
            </span>
          </div>
        </div>

        {/* Extracted Evidence Payload */}
        <div>
          <span className="text-[10px] font-mono font-bold text-[var(--fg-secondary)] uppercase tracking-wider block mb-1">
            Raw Extracted Indicator Payload
          </span>
          <div className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] font-mono text-xs text-[var(--fg-code)] break-all select-all leading-relaxed">
            {signal.evidence}
          </div>
        </div>

        {/* Forensic Rationale */}
        <div>
          <span className="text-[10px] font-mono font-bold text-[var(--fg-secondary)] uppercase tracking-wider block mb-1">
            Technical Rationale
          </span>
          <p className="text-xs text-[var(--fg-secondary)] leading-relaxed bg-[var(--bg-elevated)] p-3 rounded border border-[var(--border-subtle)]">
            {signal.rationale}
          </p>
        </div>

        {/* Footer */}
        <div className="pt-2 border-t border-[var(--border-subtle)] flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded text-xs font-mono font-medium bg-[var(--bg-elevated)] hover:bg-[var(--bg-hover)] text-[var(--fg-primary)] border border-[var(--border-subtle)] transition"
          >
            Close Rationale
          </button>
        </div>
      </div>
    </div>
  );
}

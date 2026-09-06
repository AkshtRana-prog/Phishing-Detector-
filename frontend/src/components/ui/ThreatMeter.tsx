"use client";

import React from "react";

interface ThreatMeterProps {
  score: number;
  max?: number;
  showLabel?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function ThreatMeter({
  score,
  max = 100,
  showLabel = true,
  size = "md",
  className = ""
}: ThreatMeterProps) {
  const safeScore = Math.max(0, Math.min(max, Number(score) || 0));
  const pct = Math.round((safeScore / max) * 100);

  let statusColor = "var(--state-safe-fg)";
  let statusBg = "var(--state-safe-bg)";
  let statusBorder = "var(--state-safe-border)";
  let severityLabel = "LOW RISK";

  if (safeScore >= 70) {
    statusColor = "var(--state-crit-fg)";
    statusBg = "var(--state-crit-bg)";
    statusBorder = "var(--state-crit-border)";
    severityLabel = "CRITICAL";
  } else if (safeScore >= 40) {
    statusColor = "var(--state-susp-fg)";
    statusBg = "var(--state-susp-bg)";
    statusBorder = "var(--state-susp-border)";
    severityLabel = "SUSPICIOUS";
  }

  const heights = {
    sm: "h-1.5",
    md: "h-2",
    lg: "h-2.5"
  };

  return (
    <div className={`flex flex-col gap-1 ${className}`} data-od-id="threat-meter">
      {showLabel && (
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-[10px] uppercase tracking-wider text-[var(--fg-muted)] font-semibold">
            Threat Score: <span style={{ color: statusColor }}>{severityLabel}</span>
          </span>
          <span className="text-xs font-bold tabular-nums" style={{ color: statusColor }}>
            {safeScore} <span className="text-[var(--fg-muted)] font-normal">/ {max}</span>
          </span>
        </div>
      )}
      
      {/* Precision calculation track: width calculated via CSS variables */}
      <div 
        className={`w-full bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded-full overflow-hidden ${heights[size]}`}
        style={{ "--max": max } as React.CSSProperties}
      >
        <div 
          className="h-full rounded-full transition-all duration-300 ease-out"
          style={{ 
            "--v": safeScore,
            width: "calc(var(--v) / var(--max) * 100%)",
            backgroundColor: statusColor,
            boxShadow: safeScore >= 70 ? "0 0 8px rgba(239, 68, 68, 0.4)" : "none"
          } as React.CSSProperties}
        />
      </div>
    </div>
  );
}

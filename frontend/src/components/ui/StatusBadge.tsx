"use client";

import React from "react";
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  AlertCircle, 
  CheckCircle2, 
  RefreshCw, 
  HelpCircle,
  Clock
} from "lucide-react";

export type SecurityStatus = 
  | "PHISHING" 
  | "MALICIOUS" 
  | "CRITICAL" 
  | "SUSPICIOUS" 
  | "HIGH" 
  | "MEDIUM" 
  | "SAFE" 
  | "LOW" 
  | "PENDING" 
  | "ANALYZING" 
  | "DEEPFAKE"
  | "UNKNOWN";

interface StatusBadgeProps {
  status: string;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
  className?: string;
}

export function StatusBadge({ 
  status, 
  size = "md", 
  showIcon = true,
  className = "" 
}: StatusBadgeProps) {
  const norm = (status || "UNKNOWN").toUpperCase().trim();

  let stateClass = "bg-[var(--state-neutral-bg)] border-[var(--state-neutral-border)] text-[var(--state-neutral-fg)]";
  let Icon = HelpCircle;
  let label = norm;

  if (norm === "PHISHING" || norm === "MALICIOUS" || norm === "CRITICAL" || norm === "DEEPFAKE") {
    stateClass = "bg-[var(--state-crit-bg)] border-[var(--state-crit-border)] text-[var(--state-crit-fg)]";
    Icon = norm === "CRITICAL" ? AlertTriangle : ShieldAlert;
    label = norm === "DEEPFAKE" ? "SYNTHETIC / DEEPFAKE" : norm;
  } else if (norm === "SUSPICIOUS" || norm === "HIGH" || norm === "MEDIUM") {
    stateClass = "bg-[var(--state-susp-bg)] border-[var(--state-susp-border)] text-[var(--state-susp-fg)]";
    Icon = AlertCircle;
  } else if (norm === "SAFE" || norm === "LOW" || norm === "LEGITIMATE") {
    stateClass = "bg-[var(--state-safe-bg)] border-[var(--state-safe-border)] text-[var(--state-safe-fg)]";
    Icon = norm === "SAFE" ? ShieldCheck : CheckCircle2;
  } else if (norm === "PENDING" || norm === "ANALYZING" || norm === "RUNNING") {
    stateClass = "bg-[var(--state-info-bg)] border-[var(--state-info-border)] text-[var(--state-info-fg)]";
    Icon = norm === "PENDING" ? Clock : RefreshCw;
    label = norm === "ANALYZING" ? "ANALYZING..." : "PENDING TRIAGE";
  }

  const sizeClasses = {
    sm: "text-[10px] px-1.5 py-0.5 gap-1",
    md: "text-[11px] px-2.5 py-1 gap-1.5",
    lg: "text-xs px-3 py-1.5 gap-2 font-semibold"
  };

  const iconSizes = {
    sm: "h-3 w-3",
    md: "h-3.5 w-3.5",
    lg: "h-4 w-4"
  };

  return (
    <span 
      className={`inline-flex items-center font-mono font-bold uppercase tracking-wider rounded border border-solid transition-colors duration-150 select-none ${sizeClasses[size]} ${stateClass} ${className}`}
      data-od-id={`status-badge-${norm.toLowerCase()}`}
    >
      {showIcon && (
        <Icon className={`${iconSizes[size]} shrink-0 ${norm === "ANALYZING" ? "animate-spin" : ""}`} />
      )}
      <span>{label}</span>
    </span>
  );
}

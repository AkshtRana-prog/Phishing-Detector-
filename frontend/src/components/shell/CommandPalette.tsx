"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Search,
  X,
  Grid,
  Link as LinkIcon,
  Mail,
  Terminal,
  Video,
  AlertTriangle,
  Activity,
  TrendingUp,
  FileText,
  Settings,
  Sun,
  Moon,
  LogOut,
  RefreshCw,
  ArrowRight,
} from "lucide-react";

interface CommandItem {
  id: string;
  category: "Navigation" | "Actions";
  label: string;
  sublabel?: string;
  icon: React.ComponentType<{ className?: string }>;
  action: () => void;
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  setActiveTab: (tab: string) => void;
  theme: "dark" | "light";
  setTheme: (theme: "dark" | "light" | ((prev: "dark" | "light") => "dark" | "light")) => void;
  onRefresh?: () => void;
  onLogout: () => void;
}

export function CommandPalette({
  isOpen,
  onClose,
  setActiveTab,
  theme,
  setTheme,
  onRefresh,
  onLogout,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: CommandItem[] = [
    {
      id: "nav-overview",
      category: "Navigation",
      label: "Go to Overview Dashboard",
      sublabel: "Core operations, metrics, vector breakdown",
      icon: Grid,
      action: () => setActiveTab("overview"),
    },
    {
      id: "nav-incidents",
      category: "Navigation",
      label: "Open Incident Queue",
      sublabel: "Triage active threat ledger",
      icon: AlertTriangle,
      action: () => setActiveTab("incidents"),
    },
    {
      id: "nav-investigate",
      category: "Navigation",
      label: "Open Investigation Lab",
      sublabel: "Deep multi-vector analysis sandbox",
      icon: Search,
      action: () => setActiveTab("investigate"),
    },
    {
      id: "nav-url",
      category: "Navigation",
      label: "Analyze Suspicious URL",
      sublabel: "Typosquatting, punycode & heuristics",
      icon: LinkIcon,
      action: () => setActiveTab("url_analysis"),
    },
    {
      id: "nav-email",
      category: "Navigation",
      label: "Inspect EML / Email File",
      sublabel: "RFC headers, SPF/DKIM/DMARC & NLP",
      icon: Mail,
      action: () => setActiveTab("email_analysis"),
    },
    {
      id: "nav-log",
      category: "Navigation",
      label: "Analyze Network Logs & PCAP",
      sublabel: "Packet inspection, brute-force & exploits",
      icon: Terminal,
      action: () => setActiveTab("log_analysis"),
    },
    {
      id: "nav-media",
      category: "Navigation",
      label: "Deepfake Media Forensics",
      sublabel: "Audio & video generative artifact scan",
      icon: Video,
      action: () => setActiveTab("media_analysis"),
    },
    {
      id: "nav-analytics",
      category: "Navigation",
      label: "View Threat Analytics",
      sublabel: "Time trends & vector distributions",
      icon: TrendingUp,
      action: () => setActiveTab("analytics"),
    },
    {
      id: "nav-reports",
      category: "Navigation",
      label: "Open Security Reports",
      sublabel: "PDF generation & compliance records",
      icon: FileText,
      action: () => setActiveTab("reports"),
    },
    {
      id: "nav-activity",
      category: "Navigation",
      label: "View Event Stream",
      sublabel: "Real-time telemetry and audit feed",
      icon: Activity,
      action: () => setActiveTab("activity"),
    },
    {
      id: "nav-settings",
      category: "Navigation",
      label: "Manage Platform Settings",
      sublabel: "Sensitivity thresholds and engines",
      icon: Settings,
      action: () => setActiveTab("settings"),
    },
    {
      id: "act-theme",
      category: "Actions",
      label: `Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`,
      sublabel: "Toggle console color theme",
      icon: theme === "dark" ? Sun : Moon,
      action: () => setTheme((prev) => (prev === "dark" ? "light" : "dark")),
    },
    {
      id: "act-refresh",
      category: "Actions",
      label: "Sync Threat Telemetry",
      sublabel: "Fetch latest incidents and metrics",
      icon: RefreshCw,
      action: () => {
        if (onRefresh) onRefresh();
      },
    },
    {
      id: "act-logout",
      category: "Actions",
      label: "Disconnect Session",
      sublabel: "Log out of security console",
      icon: LogOut,
      action: onLogout,
    },
  ];

  const filteredCommands = commands.filter(
    (c) =>
      c.label.toLowerCase().includes(query.toLowerCase()) ||
      (c.sublabel && c.sublabel.toLowerCase().includes(query.toLowerCase())) ||
      c.category.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filteredCommands.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % (filteredCommands.length || 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].action();
        onClose();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-start justify-center pt-16 sm:pt-24 px-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command Palette"
    >
      <div
        className="w-full max-w-xl rounded-lg border border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-2xl overflow-hidden flex flex-col animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="h-12 px-3.5 border-b border-[var(--border-subtle)] flex items-center gap-2.5 bg-[var(--bg-elevated)]/50">
          <Search className="h-4 w-4 text-[var(--fg-muted)] shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command, vector, or jump to view..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent border-0 outline-none text-xs text-[var(--fg-primary)] placeholder-[var(--fg-muted)]"
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="p-1 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] cursor-pointer"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--fg-muted)] shrink-0">
            Esc
          </kbd>
        </div>

        {/* Command List */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-1">
          {filteredCommands.length > 0 ? (
            filteredCommands.map((cmd, idx) => {
              const Icon = cmd.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={cmd.id}
                  onClick={() => {
                    cmd.action();
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded text-left transition cursor-pointer text-xs ${
                    isSelected
                      ? "bg-[var(--accent-surface)] text-[var(--accent-base)] font-medium border border-[var(--accent-base)]/25"
                      : "text-[var(--fg-secondary)] hover:bg-[var(--bg-hover)] border border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon
                      className={`h-4 w-4 shrink-0 ${
                        isSelected ? "text-[var(--accent-base)]" : "text-[var(--fg-muted)]"
                      }`}
                    />
                    <div className="min-w-0">
                      <div className="text-xs truncate font-medium text-[var(--fg-primary)]">
                        {cmd.label}
                      </div>
                      {cmd.sublabel && (
                        <div className="text-[10px] text-[var(--fg-muted)] truncate font-mono">
                          {cmd.sublabel}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[var(--bg-surface)] text-[var(--fg-muted)] border border-[var(--border-subtle)]">
                      {cmd.category}
                    </span>
                    {isSelected && <ArrowRight className="h-3 w-3 text-[var(--accent-base)]" />}
                  </div>
                </button>
              );
            })
          ) : (
            <div className="py-8 text-center text-xs text-[var(--fg-muted)]">
              No matching commands or navigation routes found.
            </div>
          )}
        </div>

        {/* Footer Hint */}
        <div className="h-9 px-3.5 border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)]/30 flex items-center justify-between text-[10px] text-[var(--fg-muted)] font-mono">
          <div className="flex items-center gap-3">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>Esc Close</span>
          </div>
          <span>Phishing Detector Console</span>
        </div>
      </div>
    </div>
  );
}

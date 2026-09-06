"use client";

import React from "react";
import {
  Shield,
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
  Search,
  LogOut,
  ChevronLeft,
} from "lucide-react";

export interface NavItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string | number;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  collapsed: boolean;
  setCollapsed: (collapsed: boolean | ((prev: boolean) => boolean)) => void;
  userEmail: string | null;
  onLogout: () => void;
  apiOffline: boolean;
  incidentCount?: number;
  pendingCount?: number;
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Core Operations",
    items: [
      { id: "overview", label: "Overview", icon: Grid },
      { id: "incidents", label: "Incident Queue", icon: AlertTriangle },
      { id: "investigate", label: "Investigation Lab", icon: Search },
    ],
  },
  {
    label: "Detection Vectors",
    items: [
      { id: "url_analysis", label: "URL Analysis", icon: LinkIcon },
      { id: "email_analysis", label: "Email Forensics", icon: Mail },
      { id: "log_analysis", label: "Logs & PCAP", icon: Terminal },
      { id: "media_analysis", label: "Media Forensics", icon: Video },
    ],
  },
  {
    label: "Intelligence & Governance",
    items: [
      { id: "analytics", label: "Threat Analytics", icon: TrendingUp },
      { id: "reports", label: "Security Reports", icon: FileText },
      { id: "activity", label: "Audit Stream", icon: Activity },
      { id: "settings", label: "Platform Settings", icon: Settings },
    ],
  },
];

export function Sidebar({
  activeTab,
  setActiveTab,
  collapsed,
  setCollapsed,
  userEmail,
  onLogout,
  apiOffline,
  incidentCount = 0,
  pendingCount = 0,
}: SidebarProps) {
  const handleItemClick = (id: string) => {
    setActiveTab(id);
    if (typeof window !== "undefined" && window.innerWidth < 768) {
      setCollapsed(true);
    }
  };

  return (
    <>
      {/* Mobile backdrop when expanded */}
      {!collapsed && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 md:hidden"
          onClick={() => setCollapsed(true)}
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed md:relative inset-y-0 left-0 flex flex-col justify-between transition-all duration-200 ease-in-out z-40 md:z-30 shrink-0 border-r border-[var(--border-subtle)] bg-[var(--bg-surface)] select-none ${
          collapsed
            ? "w-0 md:w-16 overflow-hidden md:overflow-visible -translate-x-full md:translate-x-0"
            : "w-64 translate-x-0"
        }`}
        aria-label="Primary Navigation"
      >
      {/* Brand Header */}
      <div className="h-14 border-b border-[var(--border-subtle)] flex items-center justify-between px-3.5">
        {collapsed ? (
          <button
            onClick={() => setCollapsed(false)}
            className="w-full flex items-center justify-center p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer"
            title="Expand Sidebar"
            aria-label="Expand Sidebar"
          >
            <div className="w-8 h-8 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent-base)]">
              <Shield className="h-4 w-4" />
            </div>
          </button>
        ) : (
          <div className="flex items-center justify-between w-full">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent-base)] shrink-0">
                <Shield className="h-4 w-4" />
              </div>
              <div className="flex flex-col min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="font-semibold text-xs tracking-tight text-[var(--fg-primary)] uppercase truncate">
                    Phishing Detector
                  </span>
                  <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--fg-muted)] border border-[var(--border-subtle)]">
                    v4.1
                  </span>
                </div>
                <span className="text-[10px] tracking-wider text-[var(--fg-muted)] uppercase font-mono">
                  SOC Analysis Console
                </span>
              </div>
            </div>

            <button
              onClick={() => setCollapsed(true)}
              className="p-1 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition shrink-0 cursor-pointer"
              title="Collapse Sidebar"
              aria-label="Collapse Sidebar"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto px-2.5 py-3 space-y-4" aria-label="Main Navigation">
        {NAV_GROUPS.map((group, groupIdx) => (
          <div key={groupIdx} className="space-y-1">
            {!collapsed && (
              <div className="px-2 pb-1 pt-0.5 text-[10px] font-semibold text-[var(--fg-muted)] uppercase tracking-wider font-mono">
                {group.label}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                const badgeValue =
                  item.id === "incidents" && incidentCount > 0
                    ? incidentCount
                    : item.id === "overview" && pendingCount > 0
                    ? pendingCount
                    : null;

                return (
                  <button
                    key={item.id}
                    onClick={() => handleItemClick(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs transition font-medium group text-left cursor-pointer ${
                      isActive
                        ? "bg-[var(--accent-surface)] text-[var(--accent-base)] border border-[var(--accent-base)]/30 font-semibold"
                        : "text-[var(--fg-secondary)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] border border-transparent"
                    } ${collapsed ? "justify-center px-0" : ""}`}
                    title={collapsed ? item.label : undefined}
                    aria-current={isActive ? "page" : undefined}
                  >
                    <Icon
                      className={`h-4 w-4 shrink-0 transition ${
                        isActive ? "text-[var(--accent-base)]" : "text-[var(--fg-muted)] group-hover:text-[var(--fg-primary)]"
                      }`}
                    />
                    {!collapsed && (
                      <>
                        <span className="flex-1 truncate">{item.label}</span>
                        {badgeValue !== null && (
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold tabular-nums ${
                              item.id === "incidents" && incidentCount > 0
                                ? "bg-red-500/10 text-red-400 border border-red-500/20"
                                : "bg-[var(--bg-elevated)] text-[var(--fg-muted)] border border-[var(--border-subtle)]"
                            }`}
                          >
                            {badgeValue}
                          </span>
                        )}
                      </>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer / System Health & Analyst Session */}
      <div className="border-t border-[var(--border-subtle)] p-2.5 space-y-2 bg-[var(--bg-elevated)]/40">
        {/* Backend Telemetry Pill */}
        {!collapsed ? (
          <div
            className={`flex items-center justify-between px-2.5 py-1.5 rounded border text-[11px] font-mono ${
              apiOffline
                ? "bg-[var(--state-crit-bg)] border-[var(--state-crit-border)] text-[var(--state-crit-fg)]"
                : "bg-[var(--state-safe-bg)] border-[var(--state-safe-border)] text-[var(--state-safe-fg)]"
            }`}
          >
            <div className="flex items-center gap-1.5">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  apiOffline ? "bg-red-400" : "bg-emerald-400 animate-pulse"
                }`}
              />
              <span className="font-medium text-[10px] uppercase tracking-wider">
                {apiOffline ? "API Offline" : "Engine Online"}
              </span>
            </div>
            <span className="text-[9px] text-[var(--fg-muted)]">:8000</span>
          </div>
        ) : (
          <div
            className="flex justify-center p-1.5"
            title={apiOffline ? "Backend API Offline" : "Backend Engine Online (:8000)"}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                apiOffline ? "bg-red-400" : "bg-emerald-400 animate-pulse"
              }`}
            />
          </div>
        )}

        {/* Analyst Session Card */}
        <div
          className={`flex items-center justify-between gap-2 p-1.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-surface)] ${
            collapsed ? "justify-center p-1" : ""
          }`}
        >
          {!collapsed ? (
            <div className="min-w-0 px-1">
              <div className="text-[11px] font-medium text-[var(--fg-primary)] truncate" title={userEmail || ""}>
                {userEmail || "Analyst"}
              </div>
              <div className="text-[9px] font-mono text-[var(--fg-muted)] flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-[var(--accent-base)]"></span>
                SOC Analyst
              </div>
            </div>
          ) : null}

          <button
            onClick={onLogout}
            className="p-1.5 text-[var(--fg-muted)] hover:text-red-400 hover:bg-red-500/10 rounded transition cursor-pointer shrink-0"
            title="Disconnect session"
            aria-label="Disconnect session"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </aside>
    </>
  );
}

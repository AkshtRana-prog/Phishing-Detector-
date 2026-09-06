"use client";

import React, { useState, useRef, useEffect } from "react";
import {
  Menu,
  Search,
  Sun,
  Moon,
  Zap,
  Bell,
  X,
  User,
  LogOut,
  RefreshCw,
  ChevronRight,
  ShieldAlert,
} from "lucide-react";
import { NAV_GROUPS } from "./Sidebar";

interface HeaderProps {
  activeTab: string;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean | ((prev: boolean) => boolean)) => void;
  theme: "dark" | "light";
  setTheme: (theme: "dark" | "light" | ((prev: "dark" | "light") => "dark" | "light")) => void;
  userEmail: string | null;
  onLogout: () => void;
  onOpenCommandPalette: () => void;
  onRefresh?: () => void;
  refreshing?: boolean;
  apiOffline: boolean;
  recentAlerts?: { id: string; title: string; time: string; severity: string }[];
}

export function Header({
  activeTab,
  sidebarCollapsed,
  setSidebarCollapsed,
  theme,
  setTheme,
  userEmail,
  onLogout,
  onOpenCommandPalette,
  onRefresh,
  refreshing = false,
  apiOffline,
  recentAlerts = [],
}: HeaderProps) {
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotificationsOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setProfileOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Compute breadcrumb path
  let currentGroup = "Operations";
  let currentItemLabel = "Overview";
  for (const group of NAV_GROUPS) {
    const item = group.items.find((i) => i.id === activeTab);
    if (item) {
      currentGroup = group.label;
      currentItemLabel = item.label;
      break;
    }
  }

  return (
    <header className="h-14 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-4 sm:px-6 flex items-center justify-between sticky top-0 z-40 select-none">
      {/* Left: Hamburger & Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={() => setSidebarCollapsed((prev) => !prev)}
          className="p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer"
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <Menu className="h-4 w-4" />
        </button>

        <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-1.5 text-xs">
          <span className="font-semibold text-[var(--fg-muted)] font-mono text-[11px] uppercase tracking-wider">
            Phishing Detector
          </span>
          <ChevronRight className="h-3 w-3 text-[var(--fg-muted)] shrink-0" />
          <span className="text-[var(--fg-muted)] truncate">{currentGroup}</span>
          <ChevronRight className="h-3 w-3 text-[var(--fg-muted)] shrink-0" />
          <span className="font-semibold text-[var(--fg-primary)] truncate">{currentItemLabel}</span>
        </nav>
      </div>

      {/* Center: Command Palette Trigger */}
      <div className="flex-1 max-w-md mx-3 hidden md:block">
        <button
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)]/60 text-[var(--fg-muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg-secondary)] text-xs transition cursor-pointer"
        >
          <div className="flex items-center gap-2 truncate">
            <Search className="h-3.5 w-3.5 shrink-0" />
            <span className="text-[11px] truncate">Search commands, vectors, IOCs...</span>
          </div>
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--fg-muted)] shrink-0">
            Ctrl K
          </kbd>
        </button>
      </div>

      {/* Right Controls: Refresh, Theme, Alerts, Profile */}
      <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
        {/* Mobile search button */}
        <button
          onClick={onOpenCommandPalette}
          className="md:hidden p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer"
          title="Search"
          aria-label="Search"
        >
          <Search className="h-4 w-4" />
        </button>

        {/* Real Backend Sync / Refresh */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer disabled:opacity-50"
            title="Refresh threat intelligence and active incidents"
            aria-label="Refresh data"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-[var(--accent-base)]" : ""}`} />
          </button>
        )}

        {/* Theme Toggle (Dark / Light) */}
        <button
          onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
          className="p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer"
          title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
          aria-label={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>

        {/* Alert Notifications Popover */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setNotificationsOpen((prev) => !prev)}
            className="p-1.5 rounded text-[var(--fg-muted)] hover:text-[var(--fg-primary)] hover:bg-[var(--bg-hover)] transition cursor-pointer relative"
            title="Notification Alerts"
            aria-label="Notification Alerts"
            aria-expanded={notificationsOpen}
          >
            <Bell className="h-4 w-4" />
            {recentAlerts.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
            )}
          </button>

          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 rounded-md border border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-lg z-50 p-3 flex flex-col gap-2.5">
              <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
                <span className="text-[11px] font-semibold text-[var(--fg-primary)] uppercase tracking-wider font-mono">
                  Security Alerts ({recentAlerts.length})
                </span>
                <button
                  onClick={() => setNotificationsOpen(false)}
                  className="text-[var(--fg-muted)] hover:text-[var(--fg-primary)] p-0.5 rounded cursor-pointer"
                  aria-label="Close Alerts"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>

              <div className="max-h-64 overflow-y-auto space-y-2">
                {recentAlerts.length > 0 ? (
                  recentAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-2 rounded border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs flex flex-col gap-1"
                    >
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="font-semibold text-[var(--state-crit-fg)] font-mono">
                          {alert.severity}
                        </span>
                        <span className="text-[var(--fg-muted)] font-mono">{alert.time}</span>
                      </div>
                      <p className="text-[11px] text-[var(--fg-primary)] leading-snug">{alert.title}</p>
                    </div>
                  ))
                ) : (
                  <div className="py-6 text-center text-xs text-[var(--fg-muted)]">
                    No active high-priority alert notices.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Profile Dropdown */}
        <div className="relative" ref={profileRef}>
          <button
            onClick={() => setProfileOpen((prev) => !prev)}
            className="flex items-center gap-2 p-1 pl-1.5 pr-2 rounded border border-[var(--border-subtle)] hover:border-[var(--border-strong)] bg-[var(--bg-elevated)] transition cursor-pointer text-left"
            title="Analyst Profile"
            aria-label="Analyst Profile"
            aria-expanded={profileOpen}
          >
            <div className="w-6 h-6 rounded bg-[var(--accent-surface)] border border-[var(--accent-base)]/30 flex items-center justify-center text-[var(--accent-base)] shrink-0">
              <User className="h-3.5 w-3.5" />
            </div>
            <span className="hidden sm:inline text-xs font-medium text-[var(--fg-primary)] max-w-[120px] truncate">
              {userEmail ? userEmail.split("@")[0] : "Analyst"}
            </span>
          </button>

          {profileOpen && (
            <div className="absolute right-0 mt-2 w-56 rounded-md border border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-lg z-50 p-2 flex flex-col gap-1">
              <div className="px-2.5 py-2 border-b border-[var(--border-subtle)] mb-1">
                <div className="text-xs font-semibold text-[var(--fg-primary)] truncate">
                  {userEmail || "Analyst"}
                </div>
                <div className="text-[10px] text-[var(--fg-muted)] font-mono mt-0.5">
                  SOC Triage Operator
                </div>
              </div>

              <div className="px-2.5 py-1 text-[10px] text-[var(--fg-muted)] font-mono">
                Session: {apiOffline ? "Disconnected" : "Connected (Postgres+Celery)"}
              </div>

              <button
                onClick={() => {
                  setProfileOpen(false);
                  onLogout();
                }}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs text-red-400 hover:bg-red-500/10 transition cursor-pointer mt-1 font-medium"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span>Disconnect Session</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

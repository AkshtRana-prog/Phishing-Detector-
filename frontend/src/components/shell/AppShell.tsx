"use client";

import React, { useState, useEffect } from "react";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { CommandPalette } from "./CommandPalette";
import { AlertCircle, RefreshCw, X } from "lucide-react";

interface AppShellProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  theme: "dark" | "light";
  setTheme: (theme: "dark" | "light" | ((prev: "dark" | "light") => "dark" | "light")) => void;
  userEmail: string | null;
  onLogout: () => void;
  apiOffline: boolean;
  onRefresh?: () => void;
  refreshing?: boolean;
  incidentCount?: number;
  pendingCount?: number;
  bannerMessage?: string | null;
  onDismissBanner?: () => void;
  children: React.ReactNode;
}

export function AppShell({
  activeTab,
  setActiveTab,
  theme,
  setTheme,
  userEmail,
  onLogout,
  apiOffline,
  onRefresh,
  refreshing = false,
  incidentCount = 0,
  pendingCount = 0,
  bannerMessage,
  onDismissBanner,
  children,
}: AppShellProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  // Sync theme with document element for global CSS variables
  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", theme);
    if (theme === "light") {
      root.classList.add("theme-light");
      root.classList.remove("theme-dark");
    } else {
      root.classList.add("theme-dark");
      root.classList.remove("theme-light");
    }
  }, [theme]);

  // Global Ctrl+K / Cmd+K listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div
      className={`min-h-screen flex bg-[var(--bg-canvas)] text-[var(--fg-primary)] font-sans antialiased overflow-hidden ${
        theme === "light" ? "theme-light" : "theme-dark"
      }`}
      data-theme={theme}
    >
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        userEmail={userEmail}
        onLogout={onLogout}
        apiOffline={apiOffline}
        incidentCount={incidentCount}
        pendingCount={pendingCount}
      />

      {/* Main Viewport Column */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header */}
        <Header
          activeTab={activeTab}
          sidebarCollapsed={sidebarCollapsed}
          setSidebarCollapsed={setSidebarCollapsed}
          theme={theme}
          setTheme={setTheme}
          userEmail={userEmail}
          onLogout={onLogout}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onRefresh={onRefresh}
          refreshing={refreshing}
          apiOffline={apiOffline}
        />

        {/* Global Offline Diagnostic Banner (Real Telemetry) */}
        {apiOffline && (
          <div
            role="alert"
            className="px-4 py-2 bg-[var(--state-crit-bg)] border-b border-[var(--state-crit-border)] text-[var(--state-crit-fg)] flex items-center justify-between text-xs font-mono select-none shrink-0"
          >
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>
                <strong>Backend Telemetry Offline:</strong> Unable to communicate with FastAPI gateway at :8000.
              </span>
            </div>
            {onRefresh && (
              <button
                onClick={onRefresh}
                className="px-2 py-0.5 rounded border border-[var(--state-crit-border)] hover:bg-red-500/20 text-[11px] font-semibold transition cursor-pointer flex items-center gap-1"
              >
                <RefreshCw className="h-3 w-3" /> Retry Connection
              </button>
            )}
          </div>
        )}

        {/* Optional Operational Banner Notification */}
        {bannerMessage && (
          <div
            role="status"
            className="px-4 py-2 bg-[var(--accent-surface)] border-b border-[var(--accent-base)]/30 text-[var(--fg-primary)] flex items-center justify-between text-xs select-none shrink-0"
          >
            <span>{bannerMessage}</span>
            {onDismissBanner && (
              <button
                onClick={onDismissBanner}
                className="text-[var(--fg-muted)] hover:text-[var(--fg-primary)] p-0.5 cursor-pointer"
                aria-label="Dismiss banner"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        )}

        {/* Main Content Workspace Stage */}
        <main
          className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 focus:outline-none"
          tabIndex={-1}
          id="main-content"
        >
          <div className="max-w-[1500px] w-full mx-auto">
            {children}
          </div>
        </main>
      </div>

      {/* Command Palette Overlay */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        setActiveTab={setActiveTab}
        theme={theme}
        setTheme={setTheme}
        onRefresh={onRefresh}
        onLogout={onLogout}
      />
    </div>
  );
}

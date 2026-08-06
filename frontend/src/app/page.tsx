"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Upload, 
  AlertTriangle, 
  CheckCircle2, 
  Download, 
  Activity, 
  FileText, 
  Video, 
  Music, 
  File,
  RefreshCw,
  Clock,
  Skull,
  FileSearch,
  Check,
  AlertCircle,
  TrendingUp,
  Database,
  Search,
  Cpu,
  BarChart2,
  AlertOctagon,
  CheckSquare,
  History,
  Lock,
  Mail,
  UserPlus,
  ArrowRight,
  LogOut,
  Trash2
} from "lucide-react";
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  PieChart, 
  Pie, 
  Cell 
} from "recharts";

const API_BASE = typeof window !== "undefined" ? `http://${window.location.hostname}:8000` : "http://localhost:8000";

interface Incident {
  id: string;
  timestamp: string;
  vector_type: string;
  status: string;
  severity: string;
  threat_score: number;
  target_input: string;
}

interface IncidentDetail extends Incident {
  evidences: { key: string; value: string }[];
  remediations: string[];
}

// ----------------------------------------------------
// CANVAS TRANSITION ANIMATION COMPONENT
// ----------------------------------------------------
interface CanvasAnimationProps {
  onComplete: () => void;
}

function TransitionAnimation({ onComplete }: CanvasAnimationProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    // Resize handler
    const handleResize = () => {
      if (canvas) {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
      }
    };
    window.addEventListener("resize", handleResize);

    const startTime = Date.now();
    const scanLines: { y: number; speed: number; opacity: number }[] = [
      { y: 0, speed: 3.5, opacity: 0.15 },
      { y: height * 0.3, speed: 2.5, opacity: 0.1 },
      { y: height * 0.7, speed: 4.5, opacity: 0.2 }
    ];

    // Logs to display
    const logTemplates = [
      { delay: 100, text: "[ SYSTEM ] INITIALIZING CRYPTOGRAPHIC HANDSHAKE..." },
      { delay: 300, text: "[ SECURE ] ESTABLISHING TUNNEL CONNECTIVITY ON PORT 8000..." },
      { delay: 600, text: "[ AUTH   ] ANALYST SIGNATURE VERIFIED: E-KEY OK." },
      { delay: 900, text: "[ DB     ] SYNCHRONIZING REALTIME THREAT DATABASE..." },
      { delay: 1200, text: "[ MODEL  ] DEEPFAKE DETECTION TENSORS LOADED (HEURISTIC ACTIVE)." },
      { delay: 1500, text: "[ SCANS  ] RESOLVING ENDPOINT LOG INGESTION VECTORS..." },
      { delay: 1800, text: "[ DECRYPT] DECRYPTING AGENT INTELLIGENCE PIPELINE DATA..." },
      { delay: 2100, text: "[ SYSTEM ] RESOLVING INTERACTION INTERFACE MATRIX..." },
      { delay: 2300, text: "[ SUCCESS] ACCESS GRANTED. PREPARING SOC TACTICAL TERMINAL." }
    ];

    const logs: { text: string; time: number }[] = [];

    // Matrix hex rain effect
    const gridCols = Math.floor(width / 80);
    const gridRows = Math.floor(height / 40);
    const hexMatrix: { char: string; x: number; y: number; alpha: number; speed: number }[] = [];

    for (let c = 0; c < gridCols; c++) {
      for (let r = 0; r < gridRows; r++) {
        if (Math.random() < 0.12) {
          const hexChars = "0123456789ABCDEF<>[]{}//\\$@#";
          hexMatrix.push({
            char: hexChars[Math.floor(Math.random() * hexChars.length)],
            x: c * 80 + 20,
            y: r * 40 + 20,
            alpha: Math.random() * 0.4,
            speed: 0.01 + Math.random() * 0.02
          });
        }
      }
    }

    const animate = () => {
      const elapsed = Date.now() - startTime;
      
      // Clear with dark terminal slate color
      ctx.fillStyle = "#020617";
      ctx.fillRect(0, 0, width, height);

      // 1. Draw digital background matrix grid
      ctx.strokeStyle = "rgba(15, 23, 42, 0.6)";
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Draw Hex Matrix codes
      hexMatrix.forEach(h => {
        h.alpha += h.speed;
        if (h.alpha > 0.45 || h.alpha < 0.05) {
          h.speed = -h.speed;
          if (Math.random() < 0.2) {
            const hexChars = "0123456789ABCDEF<>[]{}//\\$@#";
            h.char = hexChars[Math.floor(Math.random() * hexChars.length)];
          }
        }
        ctx.fillStyle = `rgba(6, 182, 212, ${Math.max(h.alpha, 0)})`; // Cyan
        ctx.font = "12px monospace";
        ctx.fillText(h.char, h.x, h.y);
      });

      // 3. Draw Scan lines
      scanLines.forEach(line => {
        line.y += line.speed;
        if (line.y > height) line.y = 0;
        
        ctx.fillStyle = `rgba(6, 182, 212, ${line.opacity})`;
        ctx.fillRect(0, line.y, width, 2);
        
        // Scan line shadow/glow
        const glow = ctx.createLinearGradient(0, line.y - 15, 0, line.y + 15);
        glow.addColorStop(0, "rgba(6, 182, 212, 0)");
        glow.addColorStop(0.5, `rgba(6, 182, 212, ${line.opacity * 0.4})`);
        glow.addColorStop(1, "rgba(6, 182, 212, 0)");
        ctx.fillStyle = glow;
        ctx.fillRect(0, line.y - 15, width, 30);
      });

      // 4. Draw diagnostic terminal frame at center
      const cardW = 580;
      const cardH = 340;
      const cardX = (width - cardW) / 2;
      const cardY = (height - cardH) / 2 + 30;

      // Draw loading ring in the center above diagnostic window
      const percent = Math.min(Math.floor((elapsed / 3200) * 100), 100);
      const ringRadius = 55;
      const ringX = width / 2;
      const ringY = cardY - 90;

      // Background loading circle
      ctx.strokeStyle = "#0f172a";
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.arc(ringX, ringY, ringRadius, 0, Math.PI * 2);
      ctx.stroke();

      // Glowing loading progress circle
      ctx.strokeStyle = "#06b6d4"; // Cyan
      ctx.lineWidth = 4;
      ctx.lineCap = "round";
      ctx.shadowColor = "#06b6d4";
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(ringX, ringY, ringRadius, -Math.PI / 2, -Math.PI / 2 + (Math.PI * 2 * (percent / 100)));
      ctx.stroke();
      ctx.shadowBlur = 0; // Reset

      // Percentage Text
      ctx.fillStyle = "#cbd5e1";
      ctx.font = "bold 20px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(`${percent}%`, ringX, ringY - 2);

      ctx.fillStyle = "#64748b";
      ctx.font = "10px monospace";
      ctx.fillText("ESTABLISHING LINK", ringX, ringY + 22);

      // Terminal Box
      ctx.fillStyle = "rgba(15, 23, 42, 0.85)"; // slate-900 transparent
      ctx.strokeStyle = "rgba(6, 182, 212, 0.4)";
      ctx.lineWidth = 1;
      ctx.fillRect(cardX, cardY, cardW, cardH);
      ctx.strokeRect(cardX, cardY, cardW, cardH);

      // Terminal Header
      ctx.fillStyle = "#0f172a";
      ctx.fillRect(cardX + 1, cardY + 1, cardW - 2, 28);
      ctx.strokeStyle = "rgba(30, 41, 59, 0.8)";
      ctx.beginPath();
      ctx.moveTo(cardX, cardY + 28);
      ctx.lineTo(cardX + cardW, cardY + 28);
      ctx.stroke();

      // Header content
      ctx.fillStyle = "#cbd5e1";
      ctx.font = "bold 11px monospace";
      ctx.textAlign = "left";
      ctx.fillText("TACTICAL GATEWAY AUTHENTICATOR v4.18", cardX + 15, cardY + 14);

      // Pulse security dot
      const isRed = Math.floor(elapsed / 400) % 2 === 0;
      ctx.fillStyle = isRed ? "#ef4444" : "#10b981";
      ctx.beginPath();
      ctx.arc(cardX + cardW - 20, cardY + 14, 5, 0, Math.PI * 2);
      ctx.fill();

      // Populate current logs based on delay
      logTemplates.forEach(t => {
        if (elapsed > t.delay && !logs.some(l => l.text === t.text)) {
          logs.push({ text: t.text, time: elapsed });
        }
      });

      // Draw logs in terminal
      ctx.font = "12px monospace";
      ctx.textAlign = "left";
      ctx.textBaseline = "top";

      const maxLines = 11;
      const startIdx = Math.max(0, logs.length - maxLines);
      
      for (let i = startIdx; i < logs.length; i++) {
        const log = logs[i];
        const displayY = cardY + 45 + (i - startIdx) * 25;
        
        if (log.text.includes("SUCCESS") || log.text.includes("GRANTED")) {
          ctx.fillStyle = "#10b981"; // Emerald Green for access granted
        } else if (log.text.includes("AUTH") || log.text.includes("VERIFIED")) {
          ctx.fillStyle = "#38bdf8"; // Sky Blue
        } else {
          ctx.fillStyle = "#94a3b8"; // Slate Gray
        }

        ctx.fillText(log.text, cardX + 20, displayY);
      }

      // Cursor block
      if (logs.length > 0 && elapsed < 3500) {
        const lastLineY = cardY + 45 + (logs.length - 1 - startIdx) * 25;
        const textWidth = ctx.measureText(logs[logs.length - 1].text).width;
        if (Math.floor(elapsed / 250) % 2 === 0) {
          ctx.fillStyle = "#64748b";
          ctx.fillRect(cardX + 22 + textWidth, lastLineY, 8, 14);
        }
      }

      // Laser Sweep effect at the very end (3.2s - 3.7s)
      if (elapsed >= 3200 && elapsed < 3700) {
        const sweepProgress = (elapsed - 3200) / 500;
        const sweepX = width * sweepProgress;

        ctx.strokeStyle = "rgba(6, 182, 212, 0.8)";
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.moveTo(sweepX, 0);
        ctx.lineTo(sweepX, height);
        ctx.stroke();

        // Glow of sweep
        const sweepGlow = ctx.createLinearGradient(sweepX - 40, 0, sweepX + 40, 0);
        sweepGlow.addColorStop(0, "rgba(6, 182, 212, 0)");
        sweepGlow.addColorStop(0.5, "rgba(6, 182, 212, 0.35)");
        sweepGlow.addColorStop(1, "rgba(6, 182, 212, 0)");
        ctx.fillStyle = sweepGlow;
        ctx.fillRect(sweepX - 40, 0, 80, height);

        // Flash wipe
        if (elapsed > 3550) {
          const fadeAlpha = (elapsed - 3550) / 150;
          ctx.fillStyle = `rgba(2, 6, 23, ${fadeAlpha})`;
          ctx.fillRect(0, 0, width, height);
        }
      }

      // 5. Complete Transition (3.7s)
      if (elapsed >= 3700) {
        cancelAnimationFrame(animationId);
        window.removeEventListener("resize", handleResize);
        onComplete();
        return;
      }

      animationId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", handleResize);
    };
  }, [onComplete]);

  return (
    <canvas 
      ref={canvasRef} 
      className="fixed inset-0 w-full h-full z-[9999] pointer-events-none" 
    />
  );
}

// ----------------------------------------------------
// MAIN SOC DASHBOARD COMPONENT WITH AUTH
// ----------------------------------------------------
export default function SOCDashboard() {
  // Session & Authentication
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authMessage, setAuthMessage] = useState({ text: "", isError: false });

  // Custom Cosmic Animation State
  const [runTransition, setRunTransition] = useState(false);

  // Operational incidents telemetry
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  
  // Form states
  const [urlInput, setUrlInput] = useState("");
  const [urlScanning, setUrlScanning] = useState(false);
  
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [emlScanning, setEmlScanning] = useState(false);

  const [logFile, setLogFile] = useState<File | null>(null);
  const [logScanning, setLogScanning] = useState(false);
  
  const [mediaFile, setMediaFile] = useState<File | null>(null);
  const [mediaType, setMediaType] = useState<"audio" | "video">("video");
  const [mediaScanning, setMediaScanning] = useState(false);

  // Analytics states
  const [analytics, setAnalytics] = useState({
    total_scans: 0,
    status_distribution: { PHISHING: 0, SUSPICIOUS: 0, SAFE: 0 },
    severity_distribution: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    vector_distribution: { URL: 0, Email: 0, Deepfake: 0, Log: 0 },
    time_trends: [] as any[]
  });

  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "[SECURE] Threat Detection Command Center Online. Initializing socket interfaces...",
    "[OK] Threat database successfully synced on PostgreSQL port 5433.",
    "[INFO] Active monitoring initialized on Celery worker port 6380.",
    "[SCANNER] Idle. Waiting for ingestion telemetry inputs..."
  ]);

  // Modern Date & Time clock state
  const [currentTime, setCurrentTime] = useState<Date | null>(null);

  // Incident list local filters
  const [filterVector, setFilterVector] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [filterSeverity, setFilterSeverity] = useState("ALL");
  const [filterSearch, setFilterSearch] = useState("");

  // Clock tick interval
  useEffect(() => {
    setCurrentTime(new Date());
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const downloadSummaryReport = async () => {
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/analytics/summary/report`, {
        headers: { "X-User-Email": email }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "SOC_SCANS_SUMMARY_REPORT.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (e) {
      console.error("Failed to download summary report", e);
    }
  };

  // Check login on load
  useEffect(() => {
    const saved = localStorage.getItem("soc_user_email");
    if (saved) {
      setUserEmail(saved);
      setIsLoggedIn(true);
    }
  }, []);

  // Live Terminal Stream logs effect
  useEffect(() => {
    if (!isLoggedIn) return;
    const sysLogs = [
      "Firewall status: ACTIVE. Exposing endpoints for local interface.",
      "SSH probe detected on host: port 22 blocked by threat matrix.",
      "Analyzing incoming payload vectors on active interface.",
      "Memory footprint nominal: 24% load. CPU status: COOL.",
      "Deepfake audio classifier ready (heuristic model active).",
      "All log trends initialized: brute force, SQLi, escalation scans running.",
      "Cache hit on Redis broker queue. Delivery latency: 2ms.",
      "Intrusion prevention rules parsed: local port 5433 secure."
    ];
    
    const timer = setInterval(() => {
      setTerminalLogs(prev => {
        const nextLogs = [...prev];
        if (nextLogs.length > 5) nextLogs.shift();
        const randomLog = sysLogs[Math.floor(Math.random() * sysLogs.length)];
        const now = new Date();
        const hrs = String(now.getHours()).padStart(2, '0');
        const mins = String(now.getMinutes()).padStart(2, '0');
        const secs = String(now.getSeconds()).padStart(2, '0');
        const timestamp = `${hrs}:${mins}:${secs}`;
        nextLogs.push(`[${timestamp}] [SYSTEM] ${randomLog}`);
        return nextLogs;
      });
    }, 4500);
    return () => clearInterval(timer);
  }, [isLoggedIn]);

  const fetchIncidents = async (silent = false) => {
    if (!silent) setLoadingList(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/incidents`, {
        headers: { "X-User-Email": email }
      });
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
      }
    } catch (e) {
      console.error("Failed to fetch incidents", e);
    } finally {
      if (!silent) setLoadingList(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/analytics`, {
        headers: { "X-User-Email": email }
      });
      if (res.ok) {
        const data = await res.json();
        setAnalytics(data);
      }
    } catch (e) {
      console.error("Failed to fetch analytics", e);
    }
  };

  const fetchIncidentDetail = async (id: string, silent = false) => {
    if (!silent) setLoadingDetail(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/incidents/${id}`, {
        headers: { "X-User-Email": email }
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedIncident(data);
      }
    } catch (e) {
      console.error("Failed to fetch detail", e);
    } finally {
      if (!silent) setLoadingDetail(false);
    }
  };

  const deleteIncident = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete this threat incident?")) return;
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}`, {
        method: "DELETE"
      });
      if (res.ok) {
        if (selectedId === id) {
          setSelectedId(null);
          setSelectedIncident(null);
        }
        fetchIncidents();
        fetchAnalytics();
      } else {
        alert("Failed to delete incident.");
      }
    } catch (e) {
      console.error("Failed to delete incident", e);
    }
  };

  const trainIncident = async (id: string, label: string) => {
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}/train`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label })
      });
      if (res.ok) {
        fetchIncidents();
        fetchAnalytics();
        if (selectedId === id) {
          fetchIncidentDetail(id);
        }
        alert(`Self-learning model trained successfully as: ${label}`);
      } else {
        const err = await res.json();
        alert(`Model training failed: ${err.detail || "Unknown error"}`);
      }
    } catch (e) {
      console.error("Failed to train model from incident", e);
    }
  };

  // Poll database updates when logged in
  useEffect(() => {
    if (!isLoggedIn) return;

    fetchIncidents();
    fetchAnalytics();
    
    const timer = setInterval(() => {
      fetchIncidents(true);
      fetchAnalytics();
    }, 5000);
    return () => clearInterval(timer);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn) return;

    if (selectedId) {
      const isNewSelection = !selectedIncident || selectedIncident.id !== selectedId;
      fetchIncidentDetail(selectedId, !isNewSelection);

      const timer = setInterval(() => {
        fetchIncidentDetail(selectedId, true);
      }, 3000);
      return () => clearInterval(timer);
    } else {
      setSelectedIncident(null);
    }
  }, [selectedId, isLoggedIn]);

  // Auth Submissions
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authEmail.trim() || !authPassword.trim()) return;
    setAuthLoading(true);
    setAuthMessage({ text: "", isError: false });

    try {
      const endpoint = authMode === "login" ? "/auth/login" : "/auth/signup";
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: authEmail, password: authPassword })
      });

      const data = await res.json();
      if (res.ok) {
        if (authMode === "login") {
          // Trigger blackhole sonic boom supernova transition
          setRunTransition(true);
        } else {
          setAuthMessage({
            text: "✓ Sign up complete. Verification email sent to your registered email address. Please check your inbox and click the verification link inside.",
            isError: false
          });
          setAuthEmail("");
          setAuthPassword("");
        }
      } else {
        setAuthMessage({ text: data.detail || "Authentication failed", isError: true });
      }
    } catch (err) {
      setAuthMessage({ text: "Gateway server connectivity failure", isError: true });
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("soc_user_email");
    setUserEmail(null);
    setIsLoggedIn(false);
    setSelectedId(null);
    setSelectedIncident(null);
    setAuthEmail("");
    setAuthPassword("");
    setAuthMessage({ text: "", isError: false });
  };

  // URL scanning submission
  const handleURLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setUrlScanning(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/analyze/url`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-User-Email": email
        },
        body: JSON.stringify({ url: urlInput })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedId(data.incident_id);
        setUrlInput("");
        fetchIncidents();
        fetchAnalytics();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setUrlScanning(false);
    }
  };

  // EML file upload
  const handleEMLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emlFile) return;
    setEmlScanning(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const formData = new FormData();
      formData.append("file", emlFile);
      const res = await fetch(`${API_BASE}/analyze/eml`, {
        method: "POST",
        headers: { "X-User-Email": email },
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedId(data.incident_id);
        setEmlFile(null);
        fetchIncidents();
        fetchAnalytics();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setEmlScanning(false);
    }
  };

  // Log file upload
  const handleLogScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!logFile) return;
    setLogScanning(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const formData = new FormData();
      formData.append("file", logFile);
      const res = await fetch(`${API_BASE}/analyze/log`, {
        method: "POST",
        headers: { "X-User-Email": email },
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedId(data.incident_id);
        setLogFile(null);
        fetchIncidents();
        fetchAnalytics();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLogScanning(false);
    }
  };

  // Deepfake media upload
  const handleMediaScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mediaFile) return;
    setMediaScanning(true);
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const formData = new FormData();
      formData.append("file", mediaFile);
      formData.append("media_type", mediaType);
      const res = await fetch(`${API_BASE}/analyze/deepfake`, {
        method: "POST",
        headers: { "X-User-Email": email },
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedId(data.incident_id);
        setMediaFile(null);
        fetchIncidents();
        fetchAnalytics();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setMediaScanning(false);
    }
  };

  const triggerReportDownload = (id: string) => {
    window.open(`${API_BASE}/incidents/${id}/report`, "_blank");
  };

  // UI badge styles mapping
  const getSeverityStyle = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL": 
        return "text-rose-400 bg-rose-500/10 border-rose-500/20 shadow-[0_0_12px_rgba(244,63,94,0.1)]";
      case "HIGH": 
        return "text-orange-400 bg-orange-500/10 border-orange-500/20";
      case "MEDIUM": 
        return "text-amber-400 bg-amber-500/10 border-amber-500/20";
      default: 
        return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case "PHISHING": 
        return "bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-[0_0_10px_rgba(244,63,94,0.1)]";
      case "DEEPFAKE": 
        return "bg-pink-500/10 text-pink-400 border border-pink-500/20 shadow-[0_0_10px_rgba(236,72,153,0.1)]";
      case "SUSPICIOUS": 
        return "bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-[0_0_10px_rgba(245,158,11,0.1)]";
      case "SAFE": 
      case "LEGITIMATE": 
        return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.1)]";
      default: 
        return "bg-slate-800/60 text-slate-400 border border-slate-700/50";
    }
  };

  const statusChartData = [
    { name: "Phishing", value: analytics.status_distribution.PHISHING, color: "#f43f5e" },
    { name: "Deepfake", value: (analytics.status_distribution as any).DEEPFAKE || 0, color: "#ec4899" },
    { name: "Suspicious", value: analytics.status_distribution.SUSPICIOUS, color: "#f59e0b" },
    { name: "Safe/Legit", value: analytics.status_distribution.SAFE, color: "#10b981" }
  ].filter(d => d.value > 0);

  const vectorChartData = Object.entries(analytics.vector_distribution).map(([key, val]) => ({
    name: key,
    scans: val
  }));

  // Render Login / Signup portal if not authenticated
  if (!isLoggedIn) {
    return (
      <div className="flex flex-col min-h-screen items-center justify-center bg-slate-950 text-slate-100 relative overflow-hidden px-4">
        {/* Background animation container for canvas portal transitions */}
        {runTransition && (
          <TransitionAnimation 
            onComplete={() => {
              setRunTransition(false);
              localStorage.setItem("soc_user_email", authEmail.trim().toLowerCase());
              setUserEmail(authEmail.trim().toLowerCase());
              setIsLoggedIn(true);
            }} 
          />
        )}

        {/* Futuristic Space & Time Background overlay */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-30 pointer-events-none"></div>
        <div className="absolute top-0 left-0 right-0 bottom-0 bg-[radial-gradient(circle_at_center,rgba(99,102,241,0.08)_0%,transparent_70%)] pointer-events-none"></div>
        <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-indigo-500/10 rounded-full blur-[120px] pointer-events-none animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] bg-purple-500/10 rounded-full blur-[100px] pointer-events-none animate-pulse" style={{ animationDelay: "2s" }}></div>

        {/* Auth Gate Card: Space and Time / ZK-Proven style */}
        <div className={`w-full max-w-md bg-slate-950/60 backdrop-blur-2xl border border-slate-800/80 rounded-2xl p-8 shadow-[0_0_50px_rgba(139,92,246,0.15)] relative z-10 transition-all duration-700 ${runTransition ? "scale-90 opacity-0 pointer-events-none" : ""}`}>
          
          <div className="text-center mb-8">
            {/* ZK-style central circular authenticator orb */}
            <div className="relative inline-flex items-center justify-center mb-6">
              <div className="absolute inset-0 bg-purple-500/30 rounded-full blur-xl animate-pulse"></div>
              <div className="relative w-20 h-20 rounded-full border-2 border-dashed border-purple-500/50 flex items-center justify-center bg-slate-900/90 shadow-[0_0_20px_rgba(168,85,247,0.4)] animate-[spin_40s_linear_infinite]"></div>
              <div className="absolute w-14 h-14 rounded-full border-2 border-purple-400 bg-slate-950 flex items-center justify-center shadow-inner">
                <Shield className="h-6 w-6 text-purple-400" />
              </div>
            </div>
            <h1 className="font-extrabold text-lg md:text-xl tracking-wider text-slate-100 uppercase">THREAT INTELLIGENCE</h1>
            <p className="text-xs text-purple-400 font-extrabold tracking-widest uppercase mt-1">SECURE DETECTOR PORTAL</p>
          </div>

          <form onSubmit={handleAuthSubmit} className="flex flex-col gap-4">
            
            {/* Email Field */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-[0.15em] flex items-center gap-2">
                <Mail className="h-3.5 w-3.5 text-purple-400" /> Security Identifier (Email)
              </label>
              <input 
                type="email" 
                placeholder="align.akshtrana@gmail.com" 
                value={authEmail}
                onChange={(e) => setAuthEmail(e.target.value)}
                required
                className="w-full bg-slate-900/40 border border-slate-800/80 rounded-lg py-2.5 px-3.5 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/20 transition-all font-medium shadow-inner"
              />
            </div>

            {/* Password Field */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[9px] font-bold text-slate-400 uppercase tracking-[0.15em] flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 text-purple-400" /> Access Key (Password)
              </label>
              <input 
                type="password" 
                placeholder="••••••••••••" 
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                required
                className="w-full bg-slate-900/40 border border-slate-800/80 rounded-lg py-2.5 px-3.5 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/20 transition-all shadow-inner"
              />
            </div>

            {/* Messages Display */}
            {authMessage.text && (
              <div className={`p-3 rounded-lg border text-[10px] font-semibold leading-relaxed ${authMessage.isError ? "bg-rose-950/20 border-rose-500/30 text-rose-450" : "bg-emerald-950/20 border-emerald-500/30 text-emerald-450"}`}>
                {authMessage.text}
              </div>
            )}

            {/* Action Submit Button */}
            <button 
              type="submit" 
              disabled={authLoading}
              className="w-full bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-extrabold text-[10px] tracking-[0.2em] py-3.5 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50 active:scale-[0.98] shadow-lg shadow-purple-950/30 mt-2"
            >
              {authLoading ? "PROOFING PROTOCOL..." : authMode === "login" ? "INITIALIZE ENTRY SYSTEM" : "SUBMIT ACCESS REQUEST"}
              <ArrowRight className="h-3.5 w-3.5" />
            </button>

          </form>

          {/* Toggle Login/Signup Modes */}
          <div className="border-t border-slate-900/80 mt-6 pt-4 text-center">
            {authMode === "login" ? (
              <button 
                type="button" 
                onClick={() => { setAuthMode("signup"); setAuthMessage({ text: "", isError: false }); }}
                className="text-[9px] font-bold text-slate-500 hover:text-purple-400 uppercase tracking-widest transition flex items-center justify-center gap-1.5 mx-auto"
              >
                <UserPlus className="h-3.5 w-3.5" /> Register new tactical account
              </button>
            ) : (
              <button 
                type="button" 
                onClick={() => { setAuthMode("login"); setAuthMessage({ text: "", isError: false }); }}
                className="text-[9px] font-bold text-slate-500 hover:text-purple-400 uppercase tracking-widest transition flex items-center justify-center gap-1.5 mx-auto"
              >
                <Lock className="h-3.5 w-3.5" /> Sign in with authorized account
              </button>
            )}
          </div>

        </div>
      </div>
    );
  }

  // Compute filtered incidents list
  const filteredIncidents = incidents.filter((inc) => {
    const matchVector = filterVector === "ALL" || inc.vector_type === filterVector;
    const matchStatus = filterStatus === "ALL" || inc.status.toUpperCase() === filterStatus.toUpperCase();
    const matchSeverity = filterSeverity === "ALL" || inc.severity.toUpperCase() === filterSeverity.toUpperCase();
    const matchSearch =
      !filterSearch ||
      inc.id.toLowerCase().includes(filterSearch.toLowerCase()) ||
      inc.target_input.toLowerCase().includes(filterSearch.toLowerCase());
    return matchVector && matchStatus && matchSeverity && matchSearch;
  });

  // Dashboard content if authenticated
  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/20 relative overflow-x-hidden pb-16">
      
      {/* Background Cyber Glow Grid Effect with deep shadows */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#090d16_1px,transparent_1px),linear-gradient(to_bottom,#090d16_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-40 pointer-events-none"></div>
      
      {/* Radial shadow vignettes for depth */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_40%,#02040a_100%)] pointer-events-none"></div>
      
      {/* Ambient security nebulas (Subtle warning/cyan glows) */}
      <div className="absolute top-0 left-1/3 w-[800px] h-[600px] bg-cyan-600/5 rounded-full blur-[160px] pointer-events-none"></div>
      <div className="absolute top-1/4 right-1/4 w-[500px] h-[500px] bg-rose-600/5 rounded-full blur-[140px] pointer-events-none"></div>
      <div className="absolute bottom-10 left-10 w-96 h-96 bg-purple-600/5 rounded-full blur-[100px] pointer-events-none"></div>

      {/* Header: Cyber Space Command Center HUD */}
      <header className="border-b border-slate-900 bg-slate-950/60 backdrop-blur-2xl px-8 py-4.5 flex items-center justify-between sticky top-0 z-50 shadow-2xl">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-3">
            <div className="w-2.5 h-2.5 bg-cyan-500 rounded-full animate-ping"></div>
            <span className="font-black text-base md:text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 uppercase">
              THREAT COMMAND CENTER
            </span>
          </div>
          
          <nav className="hidden lg:flex items-center gap-6 text-[9px] font-black tracking-[0.2em] text-slate-500 uppercase">
            <a href="#audit-vectors" className="hover:text-cyan-400 transition-colors text-cyan-400 border-b border-cyan-500/30 pb-0.5">[ AUDIT VECTORS ]</a>
            <a href="#triage" className="hover:text-cyan-400 transition-colors">[ OPERATIONAL TRIAGE ]</a>
            <a href="#analytics" className="hover:text-cyan-400 transition-colors">[ THREAT ANALYTICS ]</a>
          </nav>
        </div>
        
        <div className="flex items-center gap-5">
          <span className="hidden sm:inline-block text-[9px] font-bold text-slate-500 font-mono tracking-widest truncate max-w-[180px]" title={userEmail || ""}>
            ANALYST // {userEmail}
          </span>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-rose-950/20 border border-rose-500/30 text-rose-400 text-[9px] font-extrabold tracking-wider shadow-inner animate-pulse">
            SECURE ACCESS
          </div>
          <button 
            onClick={() => { fetchIncidents(); fetchAnalytics(); }}
            className="p-2 bg-slate-950/60 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-900 rounded text-slate-400 transition-all duration-200 active:scale-95 shadow-sm"
            title="Refresh Feed"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button 
            onClick={handleLogout}
            className="p-2 bg-rose-950/20 border border-rose-900/30 hover:border-rose-500/40 hover:bg-rose-950/40 rounded text-rose-400 transition-all duration-200 active:scale-95 shadow-sm flex items-center gap-1.5 text-[9px] font-black tracking-widest"
            title="Logout Session"
          >
            <LogOut className="h-3.5 w-3.5" /> DISCONNECT
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="max-w-7xl mx-auto w-full px-8 mt-8 flex flex-col gap-8 relative z-10">
        
        {/* 1. Tactical SOC Hero Terminal & Logs Console */}
        <section className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-stretch">
          
          {/* Diagnostic HUD */}
          <div className="lg:col-span-1 rounded-2xl border border-slate-900 bg-slate-950/70 p-6 flex flex-col justify-between min-h-[260px] shadow-[0_4px_30px_rgba(0,0,0,0.8)] relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">SYS_DIAG_A1</div>
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-cyan-400" />
                <span className="text-xs font-black tracking-wider text-slate-350 uppercase">SYSTEM TELEMETRY CORE</span>
              </div>
              
              <div className="flex items-center gap-4 my-4">
                <div className="relative w-20 h-20 flex items-center justify-center">
                  <div className="absolute inset-0 border border-cyan-500/10 rounded-full"></div>
                  <div className="absolute w-16 h-16 border-2 border-dashed border-cyan-500/30 rounded-full animate-[spin_10s_linear_infinite]"></div>
                  <div className="absolute w-12 h-12 border border-cyan-400/50 rounded-full animate-ping"></div>
                  <Activity className="h-5 w-5 text-cyan-400" />
                </div>
                <div className="flex-1 flex flex-col gap-1.5">
                  <div className="flex justify-between text-[9px] font-bold text-slate-500">
                    <span>IPS THREAT VECTOR</span>
                    <span className="text-cyan-400">NOMINAL</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500" style={{ width: "85%" }}></div>
                  </div>
                  <div className="flex justify-between text-[9px] font-bold text-slate-500 mt-1">
                    <span>CELERY DB LINK</span>
                    <span className="text-purple-400">SYNCED (6380)</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                    <div className="h-full bg-purple-500" style={{ width: "95%" }}></div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="border-t border-slate-900 pt-3 text-[9px] text-slate-500 leading-relaxed uppercase">
              GRID LOCATION: <span className="text-slate-300 font-bold">172.25.113.214</span> // PORT: <span className="text-slate-300 font-bold">8000</span>
            </div>
          </div>

          {/* Modern Date & Time Card */}
          <div className="lg:col-span-1 rounded-2xl border border-slate-900 bg-slate-950/70 p-6 flex flex-col justify-between min-h-[260px] shadow-[0_4px_30px_rgba(0,0,0,0.8)] relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">SYS_CLOCK_GMT</div>
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Clock className="h-4 w-4 text-purple-400 animate-pulse" />
                <span className="text-xs font-black tracking-wider text-slate-350 uppercase">Chronometer Node</span>
              </div>
              
              <div className="flex flex-col items-center justify-center py-4 bg-slate-900/10 border border-slate-900/60 rounded-xl p-4 shadow-inner">
                <div className="text-2xl font-black font-mono tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-indigo-400 to-cyan-400">
                  {currentTime ? currentTime.toLocaleTimeString() : "--:--:--"}
                </div>
                <div className="text-[9px] font-extrabold text-slate-400 uppercase tracking-widest mt-2 font-mono text-center">
                  {currentTime ? currentTime.toLocaleDateString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }) : "INITIALIZING CHRONOMETER..."}
                </div>
              </div>
            </div>
            
            <div className="border-t border-slate-900 pt-3 flex items-center justify-between text-[9px] text-slate-500 uppercase font-mono">
              <span>Timezone: {currentTime ? Intl.DateTimeFormat().resolvedOptions().timeZone : "GMT"}</span>
              <span className="text-purple-450 font-bold">
                {currentTime ? (
                  `UTC ${currentTime.getTimezoneOffset() > 0 ? "-" : "+"}${Math.abs(Math.floor(currentTime.getTimezoneOffset() / 60))}:${Math.abs(currentTime.getTimezoneOffset() % 60).toString().padStart(2, '0')}`
                ) : (
                  "UTC +00:00"
                )}
              </span>
            </div>
          </div>
          
          {/* Live Intrusion logs console */}
          <div className="lg:col-span-2 rounded-2xl border border-slate-900 bg-slate-950/70 p-6 flex flex-col justify-between min-h-[260px] shadow-[0_4px_30px_rgba(0,0,0,0.8)] relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">IDS_LOG_STREAM</div>
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Cpu className="h-4 w-4 text-rose-500" />
                <span className="text-xs font-black tracking-wider text-slate-350 uppercase">REAL-TIME THREAT LOG TERMINAL</span>
              </div>
              
              <div className="flex flex-col gap-2 font-mono text-[10px] text-slate-300 bg-slate-950/90 border border-slate-900 p-4 rounded-xl shadow-inner min-h-[140px] max-h-[140px] overflow-y-auto leading-relaxed">
                {terminalLogs.map((log, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-cyan-500 shrink-0">&gt;</span>
                    <span className={log.includes("[SYSTEM]") ? "text-slate-400" : log.includes("[OK]") ? "text-emerald-400" : log.includes("[SECURE]") ? "text-purple-400" : "text-cyan-400"}>
                      {log}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="border-t border-slate-900 pt-3 flex items-center justify-between text-[9px] text-slate-500 uppercase">
              <span>System: Monitoring local interface on PostgreSQL 5433</span>
              <span className="text-emerald-400 animate-pulse">● INTERFACING...</span>
            </div>
          </div>
          
        </section>

        {/* 2. Audit Scanner Panels (Replacing planetary style with holographic scanners) */}
        <section id="audit-vectors" className="flex flex-col gap-6">
          <div className="border-b border-slate-900/60 pb-3">
            <span className="text-xs font-black tracking-wider text-slate-500 uppercase">SYSTEM INGEST CHANNELS</span>
            <h3 className="text-lg font-extrabold text-white uppercase tracking-wider mt-1">TACTICAL VECTOR AUDIT MODULES</h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            
            {/* Panel 1: URL Scanner (Hologram Theme) */}
            <div className="group bg-slate-950/50 backdrop-blur-2xl border border-slate-900 hover:border-rose-500/40 rounded-2xl p-6 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1.5 hover:shadow-[0_4px_30px_rgba(244,63,94,0.1)] h-full">
              <div className="flex flex-col items-center text-center">
                {/* Glowing Hologram scanner circle */}
                <div className="relative w-24 h-24 mb-5 flex items-center justify-center">
                  <div className="absolute inset-0 bg-rose-500/5 rounded-full blur-xl group-hover:bg-rose-500/10 transition-all"></div>
                  
                  {/* Holographic scanning vector rings */}
                  <svg className="w-18 h-18 text-rose-500/40 drop-shadow-[0_0_8px_rgba(244,63,94,0.2)] animate-[spin_20s_linear_infinite]" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" stroke="currentColor" strokeWidth="1.5" strokeDasharray="6 6" fill="none" />
                    <circle cx="50" cy="50" r="35" stroke="currentColor" strokeWidth="1" strokeDasharray="15 8" fill="none" className="animate-[spin_8s_linear_infinite_reverse]" />
                    <circle cx="50" cy="50" r="22" stroke="currentColor" strokeWidth="2" fill="none" className="text-rose-500/80 animate-pulse" />
                    <path d="M 50 10 L 50 90 M 10 50 L 90 50" stroke="currentColor" strokeWidth="0.5" strokeDasharray="3 3" />
                  </svg>
                  
                  {/* Glowing center indicator */}
                  <div className="absolute w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_10px_#ef4444] animate-ping"></div>
                </div>
                <span className="text-[8px] font-bold tracking-[0.2em] text-rose-500 uppercase">[ AUDIT VECTOR: URL-A1 ]</span>
                <h4 className="text-xs font-black text-white uppercase tracking-widest mt-1 mb-2">URL Audit Terminal</h4>
                <p className="text-[11px] text-slate-450 leading-relaxed font-medium mb-4 min-h-[48px]">Inspect domain syntax structures, typosquat attributes, and redirections.</p>
              </div>

              <form onSubmit={handleURLScan} className="w-full mt-auto">
                <input 
                  type="text" 
                  placeholder="https://malicious-secure-access.com" 
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="w-full bg-slate-900/30 border border-slate-900 rounded py-2 px-3 text-[10px] text-slate-100 placeholder-slate-800 focus:outline-none focus:border-rose-500/60 focus:ring-1 focus:ring-rose-500/25 mb-3 transition shadow-inner font-mono"
                />
                <button 
                  type="submit" 
                  disabled={urlScanning}
                  className="w-full bg-rose-950/20 border border-rose-500/40 hover:bg-rose-900/40 text-rose-350 font-black text-[9px] tracking-widest py-3 rounded transition disabled:opacity-50 active:scale-95 shadow-md shadow-rose-950/20"
                >
                  {urlScanning ? "DECRYPTING..." : "SCAN INSTANCE"}
                </button>
              </form>
            </div>

            {/* Panel 2: EML Parser (Hologram Theme) */}
            <div className="group bg-slate-955/50 backdrop-blur-2xl border border-slate-900 hover:border-cyan-500/40 rounded-2xl p-6 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1.5 hover:shadow-[0_4px_30px_rgba(6,182,212,0.1)] h-full">
              <div className="flex flex-col items-center text-center">
                {/* Glowing Hologram scanner circle */}
                <div className="relative w-24 h-24 mb-5 flex items-center justify-center">
                  <div className="absolute inset-0 bg-cyan-500/5 rounded-full blur-xl group-hover:bg-cyan-500/10 transition-all"></div>
                  
                  {/* Holographic scanning vector rings */}
                  <svg className="w-18 h-18 text-cyan-400/40 drop-shadow-[0_0_8px_rgba(6,182,212,0.2)] animate-[spin_20s_linear_infinite]" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" stroke="currentColor" strokeWidth="1.5" strokeDasharray="8 4" fill="none" />
                    <circle cx="50" cy="50" r="32" stroke="currentColor" strokeWidth="1" strokeDasharray="10 10" fill="none" className="animate-[spin_6s_linear_infinite_reverse]" />
                    <circle cx="50" cy="50" r="20" stroke="currentColor" strokeWidth="2" fill="none" className="text-cyan-400/80 animate-pulse" />
                    <path d="M 50 10 L 50 90 M 10 50 L 90 50" stroke="currentColor" strokeWidth="0.5" strokeDasharray="2 2" />
                  </svg>
                  
                  {/* Glowing center indicator */}
                  <div className="absolute w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee] animate-ping"></div>
                </div>
                <span className="text-[8px] font-bold tracking-[0.2em] text-cyan-400 uppercase">[ AUDIT VECTOR: EML-B2 ]</span>
                <h4 className="text-xs font-black text-white uppercase tracking-widest mt-1 mb-2">Email Ingest Auditor</h4>
                <p className="text-[11px] text-slate-450 leading-relaxed font-medium mb-4 min-h-[48px]">Inspect header attributes, DKIM/DMARC flags, and attachments.</p>
              </div>

              <form onSubmit={handleEMLScan} className="w-full mt-auto">
                <div className="relative border border-dashed border-slate-900 hover:border-slate-800 rounded p-2 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                  <input 
                    type="file" 
                    accept=".eml" 
                    onChange={(e) => setEmlFile(e.target.files?.[0] || null)}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <File className="h-4 w-4 mx-auto text-slate-700 mb-1" />
                  <span className="text-[9px] text-slate-500 block truncate font-bold">
                    {emlFile ? emlFile.name : "Choose raw email (.eml)"}
                  </span>
                </div>
                <button 
                  type="submit" 
                  disabled={emlScanning || !emlFile}
                  className="w-full bg-cyan-950/20 border border-cyan-500/40 hover:bg-cyan-900/40 text-cyan-350 font-black text-[9px] tracking-widest py-3 rounded transition disabled:opacity-50 active:scale-95 shadow-md shadow-cyan-950/20"
                >
                  {emlScanning ? "AUDITING..." : "SCAN TELEMETRY"}
                </button>
              </form>
            </div>

            {/* Panel 3: Log Parser (Hologram Theme) */}
            <div className="group bg-slate-955/50 backdrop-blur-2xl border border-slate-900 hover:border-purple-500/40 rounded-2xl p-6 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1.5 hover:shadow-[0_4px_30px_rgba(139,92,246,0.1)] h-full">
              <div className="flex flex-col items-center text-center">
                {/* Glowing Hologram scanner circle */}
                <div className="relative w-24 h-24 mb-5 flex items-center justify-center">
                  <div className="absolute inset-0 bg-purple-500/5 rounded-full blur-xl group-hover:bg-purple-500/10 transition-all"></div>
                  
                  {/* Holographic scanning vector rings */}
                  <svg className="w-18 h-18 text-purple-400/40 drop-shadow-[0_0_8px_rgba(168,85,247,0.2)] animate-[spin_20s_linear_infinite]" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" stroke="currentColor" strokeWidth="1.5" strokeDasharray="10 5" fill="none" />
                    <circle cx="50" cy="50" r="30" stroke="currentColor" strokeWidth="1" strokeDasharray="8 8" fill="none" className="animate-[spin_10s_linear_infinite_reverse]" />
                    <circle cx="50" cy="50" r="18" stroke="currentColor" strokeWidth="2" fill="none" className="text-purple-400/80 animate-pulse" />
                    <path d="M 50 10 L 50 90 M 10 50 L 90 50" stroke="currentColor" strokeWidth="0.5" strokeDasharray="2 2" />
                  </svg>
                  
                  {/* Glowing center indicator */}
                  <div className="absolute w-2 h-2 rounded-full bg-purple-400 shadow-[0_0_10px_#c084fc] animate-ping"></div>
                </div>
                <span className="text-[8px] font-bold tracking-[0.2em] text-purple-400 uppercase">[ AUDIT VECTOR: LOGS-C3 ]</span>
                <h4 className="text-xs font-black text-white uppercase tracking-widest mt-1 mb-2">Logs & PCAP Auditor</h4>
                <p className="text-[11px] text-slate-450 leading-relaxed font-medium mb-4 min-h-[48px]">Trace brute force attempts, SQL injections, and decode raw Wireshark frames.</p>
              </div>

              <form onSubmit={handleLogScan} className="w-full mt-auto">
                <div className="relative border border-dashed border-slate-900 hover:border-slate-800 rounded p-2 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                  <input 
                    type="file" 
                    accept=".log,.txt,.json,.pcap,.csv" 
                    onChange={(e) => setLogFile(e.target.files?.[0] || null)}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <Database className="h-4 w-4 mx-auto text-slate-700 mb-1" />
                  <span className="text-[9px] text-slate-500 block truncate font-bold">
                    {logFile ? logFile.name : "Choose logs / PCAP file"}
                  </span>
                </div>
                <button 
                  type="submit" 
                  disabled={logScanning || !logFile}
                  className="w-full bg-purple-950/20 border border-purple-500/40 hover:bg-purple-900/40 text-purple-350 font-black text-[9px] tracking-widest py-3 rounded transition disabled:opacity-50 active:scale-95 shadow-md shadow-purple-950/20"
                >
                  {logScanning ? "PARSING..." : "AUDIT DATA"}
                </button>
              </form>
            </div>

            {/* Panel 4: Deepfake Media (Hologram Theme) */}
            <div className="group bg-slate-955/50 backdrop-blur-2xl border border-slate-900 hover:border-emerald-500/40 rounded-2xl p-6 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1.5 hover:shadow-[0_4px_30px_rgba(16,185,129,0.1)] h-full">
              <div className="flex flex-col items-center text-center">
                {/* Glowing Hologram scanner circle */}
                <div className="relative w-24 h-24 mb-5 flex items-center justify-center">
                  <div className="absolute inset-0 bg-emerald-500/5 rounded-full blur-xl group-hover:bg-emerald-500/10 transition-all"></div>
                  
                  {/* Holographic scanning vector rings */}
                  <svg className="w-18 h-18 text-emerald-400/40 drop-shadow-[0_0_8px_rgba(16,185,129,0.2)] animate-[spin_20s_linear_infinite]" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" stroke="currentColor" strokeWidth="1.5" strokeDasharray="12 6" fill="none" />
                    <circle cx="50" cy="50" r="35" stroke="currentColor" strokeWidth="1" strokeDasharray="5 5" fill="none" className="animate-[spin_12s_linear_infinite_reverse]" />
                    <circle cx="50" cy="50" r="22" stroke="currentColor" strokeWidth="2" fill="none" className="text-emerald-400/80 animate-pulse" />
                    <path d="M 50 10 L 50 90 M 10 50 L 90 50" stroke="currentColor" strokeWidth="0.5" strokeDasharray="2 2" />
                  </svg>
                  
                  {/* Glowing center indicator */}
                  <div className="absolute w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399] animate-ping"></div>
                </div>
                <span className="text-[8px] font-bold tracking-[0.2em] text-emerald-400 uppercase">[ AUDIT VECTOR: DEEP-D4 ]</span>
                <h4 className="text-xs font-black text-white uppercase tracking-widest mt-1 mb-2">Deepfake Media Inspect</h4>
                <p className="text-[11px] text-slate-450 leading-relaxed font-medium mb-4 min-h-[48px]">Analyze video frame transitions and trace synthetic vocal clones.</p>
              </div>

              <form onSubmit={handleMediaScan} className="w-full mt-auto">
                <div className="flex gap-1.5 mb-2.5">
                  <button 
                    type="button" 
                    onClick={() => setMediaType("video")}
                    className={`flex-1 flex items-center justify-center gap-1 py-1 rounded text-[8px] font-black border transition duration-200 ${mediaType === "video" ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-400 shadow-inner" : "bg-slate-900/10 border-slate-900 text-slate-650"}`}
                  >
                    VIDEO
                  </button>
                  <button 
                    type="button" 
                    onClick={() => setMediaType("audio")}
                    className={`flex-1 flex items-center justify-center gap-1 py-1 rounded text-[8px] font-black border transition duration-200 ${mediaType === "audio" ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-400 shadow-inner" : "bg-slate-900/10 border-slate-900 text-slate-650"}`}
                  >
                    AUDIO
                  </button>
                </div>
                <div className="relative border border-dashed border-slate-900 hover:border-slate-800 rounded p-2 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                  <input 
                    type="file" 
                    accept={mediaType === "video" ? "video/*" : "audio/*"}
                    onChange={(e) => setMediaFile(e.target.files?.[0] || null)}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  />
                  <Video className="h-4 w-4 mx-auto text-slate-700 mb-1" />
                  <span className="text-[9px] text-slate-500 block truncate font-bold">
                    {mediaFile ? mediaFile.name : `Select ${mediaType}`}
                  </span>
                </div>
                <button 
                  type="submit" 
                  disabled={mediaScanning || !mediaFile}
                  className="w-full bg-emerald-950/20 border border-emerald-500/40 hover:bg-emerald-900/40 text-emerald-350 font-black text-[9px] tracking-widest py-3 rounded transition disabled:opacity-50 active:scale-95 shadow-md shadow-emerald-950/20"
                >
                  {mediaScanning ? "PROCESSING..." : "CHECK MEDIA"}
                </button>
              </form>
            </div>

          </div>
        </section>

        {/* 3. Operational Triage Feed & Telemetry Graphs */}
        <div id="triage" className="grid grid-cols-1 xl:grid-cols-3 gap-8 items-stretch mt-2">
          
          {/* Left Column: SOC Queue */}
          <div className="xl:col-span-2 flex flex-col gap-6 h-full justify-between">
            
            <div className="bg-slate-950/40 backdrop-blur-2xl border border-slate-900 rounded-2xl p-6 flex-1 flex flex-col justify-between shadow-2xl relative">
              <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">SYS_TRIAGE_FEED</div>
              <div>
                <div className="flex items-center justify-between border-b border-slate-900 pb-3.5 mb-4">
                  <h2 className="text-xs md:text-sm font-extrabold tracking-wider text-slate-400 uppercase flex items-center gap-2">
                    <History className="h-4 w-4 text-cyan-400 animate-pulse" /> Operational Threat Queue
                  </h2>
                  <div className="flex items-center gap-3">
                    <span className="hidden sm:inline-block text-[10px] font-bold text-slate-500 font-mono">Telemetry: {incidents.length} logs active</span>
                    <button 
                      onClick={downloadSummaryReport}
                      className="px-2.5 py-1.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-extrabold text-[8px] tracking-widest rounded flex items-center gap-1 transition active:scale-95 shadow-lg shadow-indigo-950/20 font-mono"
                      title="Download Scans Summary"
                    >
                      <Download className="h-3 w-3" /> SUMMARY REPORT
                    </button>
                  </div>
                </div>

                {/* Filter Control Center */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 bg-slate-900/10 border border-slate-900 rounded-xl p-3.5 mb-5 shadow-inner">
                  {/* Search Input */}
                  <div className="relative col-span-1 sm:col-span-1">
                    <input 
                      type="text" 
                      placeholder="SEARCH INCIDENTS..." 
                      value={filterSearch}
                      onChange={(e) => setFilterSearch(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded px-2.5 py-1.5 pl-7 text-[9px] font-bold text-slate-100 placeholder-slate-700 focus:outline-none focus:border-cyan-500 transition-all font-mono"
                    />
                    <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-650" />
                  </div>
                  {/* Vector dropdown */}
                  <div>
                    <select 
                      value={filterVector}
                      onChange={(e) => setFilterVector(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded px-2 py-1.5 text-[9px] font-bold text-slate-350 focus:outline-none focus:border-cyan-500 transition-all cursor-pointer font-mono uppercase"
                    >
                      <option value="ALL">Vector: ALL</option>
                      <option value="URL">URL</option>
                      <option value="Email">Email</option>
                      <option value="Log">Logs</option>
                      <option value="Deepfake">Deepfakes</option>
                    </select>
                  </div>
                  {/* Status dropdown */}
                  <div>
                    <select 
                      value={filterStatus}
                      onChange={(e) => setFilterStatus(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded px-2 py-1.5 text-[9px] font-bold text-slate-350 focus:outline-none focus:border-cyan-500 transition-all cursor-pointer font-mono uppercase"
                    >
                      <option value="ALL">Status: ALL</option>
                      <option value="SAFE">SAFE</option>
                      <option value="SUSPICIOUS">SUSPICIOUS</option>
                      <option value="DEEPFAKE">DEEPFAKE</option>
                      <option value="PHISHING">PHISHING</option>
                      <option value="PENDING">PENDING</option>
                    </select>
                  </div>
                  {/* Severity dropdown */}
                  <div>
                    <select 
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value)}
                      className="w-full bg-slate-950/80 border border-slate-800 rounded px-2 py-1.5 text-[9px] font-bold text-slate-350 focus:outline-none focus:border-cyan-500 transition-all cursor-pointer font-mono uppercase"
                    >
                      <option value="ALL">Severity: ALL</option>
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </div>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-900 text-slate-500 tracking-wider font-extrabold text-[9px] uppercase">
                        <th className="py-3 px-4">Incident ID</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Vector</th>
                        <th className="py-3 px-4">Ingest Source Target</th>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredIncidents.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-16 text-center text-slate-700 font-semibold tracking-widest uppercase text-[10px]">
                            No active threat incidents matching selected filter attributes.
                          </td>
                        </tr>
                      ) : (
                        filteredIncidents.map((inc) => (
                          <tr 
                            key={inc.id} 
                            onClick={() => setSelectedId(inc.id)}
                            className={`border-b border-slate-900/40 hover:bg-slate-900/20 cursor-pointer transition-all duration-200 ${selectedId === inc.id ? "bg-slate-900/40 border-l-2 border-l-cyan-500 shadow-inner" : ""}`}
                          >
                            <td className="py-4 px-4 font-mono text-slate-350 font-bold">{inc.id.slice(0, 8)}...</td>
                            <td className="py-4 px-4 text-slate-400 font-mono">{inc.timestamp.replace("T", " ").slice(0, 16)}</td>
                            <td className="py-4 px-4">
                              <span className="font-extrabold text-slate-200">{inc.vector_type}</span>
                            </td>
                            <td className="py-4 px-4 text-slate-400 font-mono truncate max-w-[150px]" title={inc.target_input}>
                              {inc.target_input}
                            </td>
                            <td className="py-4 px-4">
                              <span className={`px-2 py-0.5 rounded border text-[9px] font-black uppercase ${getSeverityStyle(inc.severity)}`}>
                                {inc.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-4 px-4">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${getStatusBadge(inc.status)}`}>
                                {inc.status}
                              </span>
                            </td>
                            <td className="py-4 px-4 text-right">
                              <div className="flex items-center justify-end gap-1.5">
                                {inc.status !== "PENDING" && (
                                  <select 
                                    onClick={(e) => e.stopPropagation()}
                                    onChange={(e) => {
                                      e.stopPropagation();
                                      if (e.target.value) {
                                        trainIncident(inc.id, e.target.value);
                                        e.target.value = ""; 
                                      }
                                    }}
                                    className="px-1.5 py-1 text-[8px] font-bold uppercase tracking-wider bg-slate-950 border border-slate-800 hover:border-cyan-500/40 text-cyan-400 rounded focus:outline-none focus:border-cyan-500 transition cursor-pointer"
                                    defaultValue=""
                                  >
                                    <option value="" disabled className="text-slate-600">Train ML</option>
                                    <option value="PHISHING" className="text-rose-500 font-extrabold bg-slate-950">PHISHING</option>
                                    <option value="SAFE" className="text-emerald-500 font-extrabold bg-slate-950">SAFE</option>
                                    <option value="SUSPICIOUS" className="text-purple-500 font-extrabold bg-slate-950">SUSPICIOUS</option>
                                    <option value="DEEPFAKE" className="text-pink-500 font-extrabold bg-slate-950">DEEPFAKE</option>
                                  </select>
                                )}
                                
                                <button 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    triggerReportDownload(inc.id);
                                  }}
                                  disabled={inc.status === "PENDING"}
                                  className="p-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 rounded text-slate-400 transition active:scale-90 disabled:opacity-30"
                                  title="Download Report"
                                >
                                  <Download className="h-3.5 w-3.5" />
                                </button>

                                <button 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    deleteIncident(inc.id);
                                  }}
                                  className="p-1.5 bg-slate-900 border border-slate-800 hover:border-rose-900/60 hover:bg-rose-950/20 rounded text-slate-400 hover:text-rose-400 transition active:scale-90"
                                  title="Delete Scan"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
              
              <div className="text-[9px] text-slate-700 mt-6 text-center border-t border-slate-900/60 pt-4 flex items-center justify-center gap-1.5 uppercase font-bold tracking-wider">
                <Database className="h-3 w-3 text-cyan-500" /> Connection: Local PostgreSQL Database Persistent Store
              </div>
            </div>

          </div>

          {/* Right Column: In-depth Incident Profile & Telemetry Charts */}
          <div className="flex flex-col gap-6 h-full justify-between">
            
            {/* Detailed Incident Profile Panel */}
            <div className="bg-slate-950/40 backdrop-blur-2xl border border-slate-900 rounded-2xl p-6 min-h-[380px] flex flex-col justify-between shadow-2xl relative">
              <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">SYS_INSPECT_PANEL</div>
              {loadingDetail ? (
                <div className="flex-1 flex flex-col items-center justify-center py-24 text-slate-500 gap-2">
                  <RefreshCw className="h-5 w-5 animate-spin text-cyan-500" />
                  <span className="text-[9px] font-black tracking-widest uppercase text-slate-600">Decoding logs payload...</span>
                </div>
              ) : selectedIncident ? (
                <div className="flex flex-col h-full justify-between">
                  <div>
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3.5 mb-4">
                      <div>
                        <h3 className="font-extrabold text-xs md:text-sm tracking-wider text-slate-400 uppercase">Incident Profiler Inspect</h3>
                        <span className="font-mono text-[10px] text-slate-500">{selectedIncident.id}</span>
                      </div>
                      {selectedIncident.status === "PHISHING" && <Skull className="h-5 w-5 text-rose-500 animate-pulse" />}
                    </div>
                    {/* Threat Score Progress bar */}
                    <div className="mb-5 bg-slate-900/20 border border-slate-900 rounded-xl p-3.5 shadow-inner">
                      <div className="flex justify-between text-[10px] font-extrabold tracking-wider uppercase mb-1.5 font-mono">
                        <span className="text-slate-550">Threat Rating</span>
                        <span className={(selectedIncident.status === "PHISHING" || selectedIncident.status === "DEEPFAKE") ? "text-rose-450" : selectedIncident.status === "SUSPICIOUS" ? "text-amber-450" : "text-emerald-450"}>
                          {selectedIncident.threat_score}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                        <div 
                          className={`h-full transition-all duration-1000 ${(selectedIncident.status === "PHISHING" || selectedIncident.status === "DEEPFAKE") ? "bg-gradient-to-r from-rose-600 to-rose-400" : selectedIncident.status === "SUSPICIOUS" ? "bg-gradient-to-r from-amber-600 to-amber-400" : "bg-gradient-to-r from-emerald-600 to-emerald-400"}`} 
                          style={{ width: `${selectedIncident.threat_score}%` }}
                        ></div>
                      </div>
                    </div>

                    {/* Operational fields */}
                    <div className="grid grid-cols-2 gap-4 text-[10px] mb-5 bg-slate-900/10 p-3.5 rounded-xl border border-slate-900/60 shadow-inner font-mono">
                      <div>
                        <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Ingest Vector</span>
                        <span className="font-extrabold text-slate-200">{selectedIncident.vector_type}</span>
                      </div>
                      <div>
                        <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Severity Rating</span>
                        <span className={`font-extrabold ${getSeverityStyle(selectedIncident.severity).split(" ")[0]}`}>{selectedIncident.severity}</span>
                      </div>
                      <div>
                        <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Classification</span>
                        <span className="font-bold text-slate-200">{selectedIncident.status}</span>
                      </div>
                      <div>
                        <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Time Logged</span>
                        <span className="font-semibold text-slate-350">{selectedIncident.timestamp}</span>
                      </div>
                      {selectedIncident.vector_type === "Log" && (
                        <div className="col-span-2 border-t border-slate-900 pt-2.5 mt-1">
                          <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Attack Monitored</span>
                          <span className="font-extrabold text-rose-400 uppercase animate-pulse">
                            {selectedIncident.evidences.find(e => e.key === "Attack Type")?.value || "ANOMALOUS PROBING"}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Evidence List */}
                    <div className="mb-5">
                      <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Indicators of Compromise</h4>
                      <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1">
                        {selectedIncident.evidences.length === 0 ? (
                          <div className="text-xs text-slate-600 italic flex items-center gap-1.5 py-1">
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" /> Incident safe. No IoC flags.
                          </div>
                        ) : (
                          selectedIncident.evidences.map((ev, i) => (
                            <div key={i} className="bg-slate-950/80 border border-slate-900 rounded p-2.5 text-[10px] leading-relaxed shadow-sm font-mono">
                              <span className="font-bold text-slate-500 block mb-0.5 text-[8px] uppercase tracking-wider">{ev.key}</span>
                              <span className="text-slate-300">{ev.value}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    {/* Remediations */}
                    <div className="mb-6">
                      <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">SOC Containment Actions</h4>
                      <ul className="list-none text-[10px] text-slate-300 flex flex-col gap-2">
                        {selectedIncident.remediations.map((rem, i) => (
                          <li key={i} className="flex gap-2 items-start bg-slate-900/30 p-2.5 rounded border border-slate-900 shadow-sm leading-relaxed font-mono">
                            {selectedIncident.status === "PHISHING" ? (
                              <AlertCircle className="h-4 w-4 text-rose-500 shrink-0 mt-0.5" />
                            ) : (
                              <Check className="h-4 w-4 text-emerald-500 shrink-0 mt-0.5" />
                            )}
                            <span>{rem}</span>
                          </li>
                        ))}
                        {selectedIncident.remediations.length === 0 && (
                          <li className="text-xs text-slate-600 italic flex items-center gap-1.5 py-1">
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" /> Incident safe. No containment required.
                          </li>
                        )}
                      </ul>
                    </div>
                  </div>

                  <button 
                    onClick={() => triggerReportDownload(selectedIncident.id)}
                    disabled={selectedIncident.status === "PENDING"}
                    className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-slate-100 font-extrabold text-[9px] tracking-widest py-3.5 rounded flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 mt-auto shadow-lg shadow-emerald-950/20 active:scale-95 font-mono"
                  >
                    <Download className="h-3.5 w-3.5" /> DOWNLOAD INCIDENT REPORT (PDF)
                  </button>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-500 py-24 border border-dashed border-slate-900 rounded-xl bg-slate-950/20">
                  <FileSearch className="h-8 w-8 text-slate-800 mb-2" />
                  <span className="text-[9px] font-extrabold tracking-widest uppercase text-slate-400 text-center px-4 leading-relaxed">Select an incident from triage feed to display tactical telemetry.</span>
                </div>
              )}
            </div>

            {/* Operational Metrics Charts */}
            <div id="analytics" className="bg-slate-955/40 backdrop-blur-2xl border border-slate-900 rounded-2xl p-6 shadow-2xl relative">
              <div className="absolute top-0 right-0 p-2 text-[8px] text-slate-700 font-mono">ANALYTICS_CORE</div>
              <h2 className="text-xs md:text-sm font-extrabold tracking-wider text-slate-400 uppercase mb-4 flex items-center gap-2">
                <BarChart2 className="h-4 w-4 text-cyan-400" /> Threat Analytics
              </h2>

              <div className="flex flex-col gap-6">
                {/* Pie Chart */}
                {statusChartData.length > 0 ? (
                  <div>
                    <h4 className="text-xs font-bold text-slate-450 mb-2.5 uppercase tracking-wider">Classification Ratios</h4>
                    <div className="h-[120px] flex items-center justify-between">
                      <div className="w-[120px] h-[120px]">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={statusChartData}
                              cx="50%"
                              cy="50%"
                              innerRadius={25}
                              outerRadius={45}
                              paddingAngle={6}
                              dataKey="value"
                              isAnimationActive={false}
                            >
                              {statusChartData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                              ))}
                            </Pie>
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="flex-1 text-[10px] pl-4 flex flex-col gap-2 font-semibold font-mono">
                        {statusChartData.map((d, i) => (
                          <div key={i} className="flex items-center justify-between">
                            <span className="flex items-center gap-1.5 text-slate-450">
                              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                              {d.name}
                            </span>
                            <span className="font-extrabold text-slate-200">{d.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-[10px] text-slate-500 italic text-center py-4">Threat ratio data pending.</div>
                )}

                {/* Bar Chart */}
                <div>
                  <h4 className="text-xs font-bold text-slate-450 mb-2.5 uppercase tracking-wider">Scan Channels</h4>
                  <div className="h-[125px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={vectorChartData} margin={{ top: 5, right: 5, left: -28, bottom: 5 }}>
                        <XAxis dataKey="name" stroke="#1e293b" fontSize={9} tickLine={false} />
                        <YAxis stroke="#1e293b" fontSize={9} tickLine={false} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: "#020617", border: "1px solid #1e293b", fontSize: 9 }}
                          cursor={{ fill: "rgba(6, 182, 212, 0.02)" }}
                        />
                        <Bar 
                          dataKey="scans" 
                          fill="#06b6d4" 
                          radius={[2, 2, 0, 0]}
                          isAnimationActive={false}
                        >
                          {vectorChartData.map((entry, index) => (
                            <Cell 
                              key={`cell-${index}`} 
                              fill={entry.name === "URL" ? "#ef4444" : entry.name === "Email" ? "#06b6d4" : entry.name === "Log" ? "#a855f7" : "#10b981"} 
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            </div>

          </div>

        </div>

      </div>

      {/* Footer: SOC Operational Integrity & Contact */}
      <footer className="w-full mt-16 border-t border-slate-900 bg-slate-950/60 backdrop-blur-2xl py-12 px-8 relative z-20">
        <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8">
          
          {/* Column 1: Brand & Status */}
          <div className="flex flex-col gap-3 md:col-span-2">
            <div className="flex items-center gap-2.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="font-extrabold text-[11px] tracking-wider text-slate-350 uppercase">
                THREAT COMMAND CENTER
              </span>
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed max-w-sm font-medium">
              Enterprise security audit pipeline for multi-vector threat ingestion. Decodes and mitigates malicious payload signatures, Wireshark flows, and synthetic media.
            </p>
            <div className="text-[9px] text-slate-650 font-bold uppercase mt-2">
              SYSTEM STATUS: SECURE (172.25.113.214) // PORT: 8000
            </div>
          </div>

          {/* Column 2: Lead Architect Contact */}
          <div className="flex flex-col gap-3">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest border-b border-slate-900/60 pb-1.5">
              LEAD ARCHITECT
            </span>
            <div className="flex flex-col gap-2 font-medium">
              <span className="text-[11px] text-slate-200">Aksht Rana</span>
              <span className="text-[10px] text-slate-500">Security Research Engineer</span>
            </div>
          </div>

          {/* Column 3: Communications Gate */}
          <div className="flex flex-col gap-3">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest border-b border-slate-900/60 pb-1.5">
              COMMUNICATIONS GATE
            </span>
            <div className="flex flex-col gap-2.5 text-[10px] text-slate-455 font-semibold">
              <a 
                href="mailto:align.akshtrana@gmail.com" 
                className="hover:text-cyan-400 transition-colors flex items-center gap-2"
              >
                <Mail className="h-3.5 w-3.5 text-cyan-500" />
                align.akshtrana@gmail.com
              </a>
              <a 
                href="https://www.linkedin.com/in/aksht-rana-009515373/" 
                target="_blank" 
                rel="noopener noreferrer" 
                className="hover:text-cyan-400 transition-colors flex items-center gap-2"
              >
                <svg className="h-3.5 w-3.5 text-cyan-500 fill-current" viewBox="0 0 24 24">
                  <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.779-1.75-1.75s.784-1.75 1.75-1.75 1.75.779 1.75 1.75-.784 1.75-1.75 1.75zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/>
                </svg>
                LinkedIn Profile
              </a>
            </div>
          </div>

        </div>

        <div className="max-w-7xl mx-auto border-t border-slate-900/60 mt-10 pt-6 flex flex-col sm:flex-row items-center justify-between text-[9px] text-slate-655 font-bold uppercase tracking-wider gap-4">
          <span>&copy; {new Date().getFullYear()} THREAT COMMAND CENTER. ALL SYSTEMS SHIELDED.</span>
          <div className="flex items-center gap-4">
            <span>[ STACK: FASTAPI / NEXT.JS / CELERY / REDIS / POSTGRES ]</span>
          </div>
        </div>
      </footer>

    </div>
  );
}

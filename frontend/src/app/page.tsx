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
  LogOut
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

  // Check login on load
  useEffect(() => {
    const saved = localStorage.getItem("soc_user_email");
    if (saved) {
      setUserEmail(saved);
      setIsLoggedIn(true);
    }
  }, []);

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

        {/* Futuristic Background overlay */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#0e172c_1px,transparent_1px),linear-gradient(to_bottom,#0e172c_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-40 pointer-events-none"></div>
        <div className="absolute top-1/4 left-1/4 w-80 h-80 bg-blue-500/5 rounded-full blur-[100px] pointer-events-none"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-[120px] pointer-events-none"></div>

        {/* Auth Gate Card */}
        <div className={`w-full max-w-md bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-2xl p-8 shadow-2xl relative z-10 transition-all duration-500 ${runTransition ? "scale-90 opacity-0 pointer-events-none" : ""}`}>
          
          <div className="text-center mb-8">
            <div className="inline-flex bg-gradient-to-br from-slate-900 to-slate-950 p-3.5 rounded-2xl border border-cyan-500/45 shadow-[0_0_15px_rgba(6,182,212,0.25)] text-cyan-400 mb-4 animate-pulse">
              <Shield className="h-8 w-8" />
            </div>
            <h1 className="font-black text-lg tracking-widest text-slate-100 uppercase">THREAT MONITOR GATEWAY</h1>
            <p className="text-[10px] text-slate-400 font-extrabold tracking-widest uppercase mt-1">AUTHENTICATION PROTOCOL SECURITY REQUIRED</p>
          </div>

          <form onSubmit={handleAuthSubmit} className="flex flex-col gap-4">
            
            {/* Email Field */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-bold text-slate-550 uppercase tracking-widest flex items-center gap-2">
                <Mail className="h-3.5 w-3.5 text-cyan-400" /> Security Identifier (Email)
              </label>
              <input 
                type="email" 
                placeholder="align.akshtrana@gmail.com" 
                value={authEmail}
                onChange={(e) => setAuthEmail(e.target.value)}
                required
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg py-2.5 px-3.5 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/20 transition-all font-medium"
              />
            </div>

            {/* Password Field */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-bold text-slate-550 uppercase tracking-widest flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 text-cyan-400" /> Security Access Key (Password)
              </label>
              <input 
                type="password" 
                placeholder="••••••••••••" 
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                required
                className="w-full bg-slate-950/60 border border-slate-800 rounded-lg py-2.5 px-3.5 text-xs text-slate-100 placeholder-slate-700 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/20 transition-all"
              />
            </div>

            {/* Messages Display */}
            {authMessage.text && (
              <div className={`p-3 rounded-lg border text-[10px] font-semibold leading-relaxed ${authMessage.isError ? "bg-rose-950/30 border-rose-500/30 text-rose-400" : "bg-emerald-950/30 border-emerald-500/30 text-emerald-400"}`}>
                {authMessage.text}
              </div>
            )}

            {/* Action Submit Button */}
            <button 
              type="submit" 
              disabled={authLoading}
              className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-slate-950 font-black text-[10px] tracking-widest py-3.5 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50 active:scale-95 shadow-lg shadow-cyan-950/20 mt-2"
            >
              {authLoading ? "PROCESSING PROTOCOL..." : authMode === "login" ? "REQUEST ENTRY SYSTEM" : "SUBMIT ACCESS REQUEST"}
              <ArrowRight className="h-3.5 w-3.5" />
            </button>

          </form>

          {/* Toggle Login/Signup Modes */}
          <div className="border-t border-slate-900/60 mt-6 pt-4 text-center">
            {authMode === "login" ? (
              <button 
                type="button" 
                onClick={() => { setAuthMode("signup"); setAuthMessage({ text: "", isError: false }); }}
                className="text-[10px] font-bold text-slate-500 hover:text-cyan-400 uppercase tracking-widest transition flex items-center justify-center gap-1.5 mx-auto"
              >
                <UserPlus className="h-3.5 w-3.5" /> Register new tactical account
              </button>
            ) : (
              <button 
                type="button" 
                onClick={() => { setAuthMode("login"); setAuthMessage({ text: "", isError: false }); }}
                className="text-[10px] font-bold text-slate-500 hover:text-cyan-400 uppercase tracking-widest transition flex items-center justify-center gap-1.5 mx-auto"
              >
                <Lock className="h-3.5 w-3.5" /> Sign in with authorized account
              </button>
            )}
          </div>

        </div>
      </div>
    );
  }

  // Dashboard content if authenticated
  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/20 relative overflow-x-hidden pb-12">
      
      {/* Background Cyber Glow Grid Effect */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0e172c_1px,transparent_1px),linear-gradient(to_bottom,#0e172c_1px,transparent_1px)] bg-[size:3.5rem_3.5rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-40 pointer-events-none"></div>
      <div className="absolute top-0 right-1/4 w-[500px] h-[500px] bg-blue-500/5 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-10 left-10 w-96 h-96 bg-indigo-500/5 rounded-full blur-[100px] pointer-events-none"></div>

      {/* Top Futuristic Header */}
      <header className="border-b border-slate-900/80 bg-slate-950/70 backdrop-blur-xl px-6 py-4 flex items-center justify-between sticky top-0 z-50 shadow-lg shadow-slate-950/60">
        <div className="flex items-center gap-3.5">
          <div className="relative">
            <div className="absolute inset-0 bg-cyan-500/30 rounded-xl blur-md animate-pulse"></div>
            <div className="relative bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 p-2.5 rounded-xl border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.2)] text-cyan-400">
              <Shield className="h-6 w-6" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="font-black text-sm tracking-widest text-slate-100 uppercase">PHISHING & DEEPFAKE PLATFORM</h1>
              <span className="text-[9px] font-black px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 tracking-widest">PRO</span>
            </div>
            <p className="text-[10px] text-slate-400 font-bold tracking-widest uppercase flex items-center gap-1.5 mt-1">
              <Cpu className="h-3 w-3 text-cyan-500" /> THREAT DETECTION TACTICAL CENTER
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <span className="text-[10px] font-bold text-slate-500 font-mono tracking-wider truncate max-w-[180px]" title={userEmail || ""}>
            {userEmail}
          </span>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/30 border border-emerald-500/40 text-emerald-400 text-[10px] font-extrabold tracking-wider shadow-inner">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping"></span>
            LIVE
          </div>
          <button 
            onClick={() => { fetchIncidents(); fetchAnalytics(); }}
            className="p-2 bg-slate-900/40 border border-slate-800 hover:border-slate-700 hover:bg-slate-900 rounded-lg text-slate-300 transition-all duration-200 active:scale-95 shadow-sm"
            title="Refresh Feed"
          >
            <RefreshCw className="h-4 w-4 text-slate-300" />
          </button>
          <button 
            onClick={handleLogout}
            className="p-2 bg-rose-950/20 border border-rose-900/30 hover:border-rose-500/40 hover:bg-rose-950/40 rounded-lg text-rose-400 transition-all duration-200 active:scale-95 shadow-sm flex items-center gap-1.5 text-[9px] font-black tracking-widest"
            title="Logout Session"
          >
            <LogOut className="h-4 w-4" /> LOGOUT
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="max-w-7xl mx-auto w-full px-6 mt-6 flex flex-col gap-6 relative z-10">
        
        {/* Real-time Telemetry Dashboard Counters */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-4.5 flex items-center justify-between shadow-xl hover:-translate-y-0.5 transition-all duration-300 hover:border-slate-800/80">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Total Inspected</span>
              <span className="text-2xl font-black text-slate-200 mt-1 block">{analytics.total_scans}</span>
            </div>
            <div className="p-2.5 bg-blue-950/30 border border-blue-500/20 text-blue-400 rounded-xl">
              <Activity className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-4.5 flex items-center justify-between shadow-xl hover:-translate-y-0.5 transition-all duration-300 hover:border-slate-800/80">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Phishing Flagged</span>
              <span className="text-2xl font-black text-rose-400 mt-1 block">{analytics.status_distribution.PHISHING}</span>
            </div>
            <div className="p-2.5 bg-rose-950/30 border border-rose-500/20 text-rose-400 rounded-xl">
              <AlertOctagon className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-4.5 flex items-center justify-between shadow-xl hover:-translate-y-0.5 transition-all duration-300 hover:border-slate-800/80">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Suspicious Logs</span>
              <span className="text-2xl font-black text-amber-400 mt-1 block">{analytics.status_distribution.SUSPICIOUS}</span>
            </div>
            <div className="p-2.5 bg-amber-950/30 border border-amber-500/20 text-amber-400 rounded-xl">
              <AlertTriangle className="h-5 w-5" />
            </div>
          </div>

          <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-4.5 flex items-center justify-between shadow-xl hover:-translate-y-0.5 transition-all duration-300 hover:border-slate-800/80">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Mitigated / Safe</span>
              <span className="text-2xl font-black text-emerald-400 mt-1 block">{analytics.status_distribution.SAFE}</span>
            </div>
            <div className="p-2.5 bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 rounded-xl">
              <CheckSquare className="h-5 w-5" />
            </div>
          </div>

        </section>

        {/* Dashboard Workspace grid */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-stretch">
          
          {/* Left Column: Upload Portals & Active triage */}
          <div className="xl:col-span-2 flex flex-col gap-6 h-full justify-between">
            
            {/* Actionable Ingestion Channels */}
            <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-5 shadow-2xl">
              <h2 className="text-[10px] font-extrabold tracking-widest text-slate-500 uppercase mb-4 flex items-center gap-2">
                <Upload className="h-4 w-4 text-cyan-400" /> Ingestion Channels
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
                
                {/* URL Scanner */}
                <div className="group bg-slate-950/50 border border-slate-900 hover:border-cyan-500/30 hover:bg-slate-950/80 rounded-xl p-5 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-cyan-500/5 h-full">
                  <div>
                    <div className="flex items-center justify-between mb-3.5">
                      <span className="text-[9px] font-extrabold tracking-widest text-cyan-400 uppercase">URL Scan Vector</span>
                      <div className="p-1.5 bg-cyan-950/30 text-cyan-400 rounded-xl border border-cyan-500/20 transition-all group-hover:scale-110">
                        <Activity className="h-4 w-4" />
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-4.5 leading-relaxed font-medium">Verify domain syntax details, certificate existence, and redirect patterns.</p>
                  </div>
                  
                  <form onSubmit={handleURLScan}>
                    <input 
                      type="text" 
                      placeholder="https://malicious-login.com" 
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      className="w-full bg-slate-900/40 border border-slate-800 rounded-lg py-2 px-3 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/20 mb-3 transition"
                    />
                    <button 
                      type="submit" 
                      disabled={urlScanning}
                      className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-slate-950 font-black text-[10px] tracking-widest py-3 rounded-lg transition disabled:opacity-50 active:scale-95 shadow-lg shadow-cyan-950/20"
                    >
                      {urlScanning ? "ANALYZING..." : "SCAN INSTANCE"}
                    </button>
                  </form>
                </div>

                {/* Email File Upload */}
                <div className="group bg-slate-950/50 border border-slate-900 hover:border-indigo-500/30 hover:bg-slate-950/80 rounded-xl p-5 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-indigo-500/5 h-full">
                  <div>
                    <div className="flex items-center justify-between mb-3.5">
                      <span className="text-[9px] font-extrabold tracking-widest text-indigo-400 uppercase">EML Ingest Vector</span>
                      <div className="p-1.5 bg-indigo-950/30 text-indigo-400 rounded-xl border border-indigo-500/20 transition-all group-hover:scale-110">
                        <FileText className="h-4 w-4" />
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-4.5 leading-relaxed font-medium">Extract validation logs (SPF/DKIM/DMARC) and scan attachments.</p>
                  </div>
                  
                  <form onSubmit={handleEMLScan}>
                    <div className="relative border border-dashed border-slate-800 group-hover:border-slate-700 rounded-lg p-3 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                      <input 
                        type="file" 
                        accept=".eml" 
                        onChange={(e) => setEmlFile(e.target.files?.[0] || null)}
                        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      />
                      <File className="h-6 w-6 mx-auto text-slate-650 mb-1" />
                      <span className="text-[10px] text-slate-400 block truncate font-medium">
                        {emlFile ? emlFile.name : "Select raw email (.eml)"}
                      </span>
                    </div>
                    <button 
                      type="submit" 
                      disabled={emlScanning || !emlFile}
                      className="w-full bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-slate-100 font-extrabold text-[10px] tracking-widest py-3 rounded-lg transition disabled:opacity-50 active:scale-95 shadow-lg shadow-indigo-950/20"
                    >
                      {emlScanning ? "PARSING LOG..." : "SCAN MAIL"}
                    </button>
                  </form>
                </div>

                {/* Log File Ingestion Channel */}
                <div className="group bg-slate-950/50 border border-slate-900 hover:border-emerald-500/30 hover:bg-slate-950/80 rounded-xl p-5 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-emerald-500/5 h-full">
                  <div>
                    <div className="flex items-center justify-between mb-3.5">
                      <span className="text-[9px] font-extrabold tracking-widest text-emerald-400 uppercase">Log Ingest Vector</span>
                      <div className="p-1.5 bg-emerald-950/30 text-emerald-400 rounded-xl border border-emerald-500/20 transition-all group-hover:scale-110">
                        <FileSearch className="h-4 w-4" />
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-4.5 leading-relaxed font-medium">Parse text/syslog/PCAP logs to extract external IPs, attack signatures, and phishing URLs.</p>
                  </div>
                  
                  <form onSubmit={handleLogScan}>
                    <div className="relative border border-dashed border-slate-800 group-hover:border-slate-700 rounded-lg p-3 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                      <input 
                        type="file" 
                        accept=".log,.txt,.json,.pcap,.csv" 
                        onChange={(e) => setLogFile(e.target.files?.[0] || null)}
                        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      />
                      <Database className="h-6 w-6 mx-auto text-slate-650 mb-1" />
                      <span className="text-[10px] text-slate-400 block truncate font-medium">
                        {logFile ? logFile.name : "Select log file (.log, .txt)"}
                      </span>
                    </div>
                    <button 
                      type="submit" 
                      disabled={logScanning || !logFile}
                      className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-slate-100 font-extrabold text-[10px] tracking-widest py-3 rounded-lg transition disabled:opacity-50 active:scale-95 shadow-lg shadow-emerald-950/20"
                    >
                      {logScanning ? "PARSING LOG..." : "SCAN LOG"}
                    </button>
                  </form>
                </div>

                {/* Deepfake Upload */}
                <div className="group bg-slate-955/50 border border-slate-900 hover:border-rose-500/30 hover:bg-slate-950/80 rounded-xl p-5 flex flex-col justify-between transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-rose-500/5 h-full">
                  <div>
                    <div className="flex items-center justify-between mb-3.5">
                      <span className="text-[9px] font-extrabold tracking-widest text-rose-400 uppercase">Deepfake Ingest</span>
                      <div className="p-1.5 bg-rose-955/30 text-rose-400 rounded-xl border border-rose-500/20 transition-all group-hover:scale-110">
                        <Video className="h-4 w-4" />
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-4.5 leading-relaxed font-medium">Test media files for blending artifacts (video) or synthetic frequencies (audio).</p>
                  </div>
                  
                  <form onSubmit={handleMediaScan}>
                    <div className="flex gap-2 mb-3">
                      <button 
                        type="button" 
                        onClick={() => setMediaType("video")}
                        className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-[9px] font-extrabold border transition duration-200 ${mediaType === "video" ? "bg-rose-955/50 border-rose-800/80 text-rose-400 shadow-inner" : "bg-slate-900/20 border-slate-800 text-slate-400"}`}
                      >
                        <Video className="h-3.5 w-3.5" /> VIDEO
                      </button>
                      <button 
                        type="button" 
                        onClick={() => setMediaType("audio")}
                        className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-[9px] font-extrabold border transition duration-200 ${mediaType === "audio" ? "bg-rose-955/50 border-rose-800/80 text-rose-400 shadow-inner" : "bg-slate-900/20 border-slate-800 text-slate-400"}`}
                      >
                        <Music className="h-3.5 w-3.5" /> AUDIO
                      </button>
                    </div>
                    <div className="relative border border-dashed border-slate-800 group-hover:border-slate-700 rounded-lg p-2.5 text-center cursor-pointer mb-3 transition bg-slate-900/10">
                      <input 
                        type="file" 
                        accept={mediaType === "video" ? "video/*" : "audio/*"}
                        onChange={(e) => setMediaFile(e.target.files?.[0] || null)}
                        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      />
                      <Upload className="h-5 w-5 mx-auto text-slate-650 mb-1" />
                      <span className="text-[10px] text-slate-400 block truncate font-medium">
                        {mediaFile ? mediaFile.name : `Select ${mediaType}`}
                      </span>
                    </div>
                    <button 
                      type="submit" 
                      disabled={mediaScanning || !mediaFile}
                      className="w-full bg-gradient-to-r from-rose-600 to-pink-600 hover:from-rose-500 hover:to-pink-500 text-slate-100 font-extrabold text-[10px] tracking-widest py-3 rounded-lg transition disabled:opacity-50 active:scale-95 shadow-lg shadow-rose-950/20"
                    >
                      {mediaScanning ? "RUNNING MODEL..." : "CHECK MEDIA"}
                    </button>
                  </form>
                </div>

              </div>
            </div>

            {/* Active Triage Table */}
            <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-900 rounded-xl p-5 flex-1 flex flex-col justify-between shadow-2xl">
              <div>
                <h2 className="text-[10px] font-extrabold tracking-widest text-slate-500 uppercase mb-4 flex items-center gap-2">
                  <History className="h-4 w-4 text-emerald-400" /> Operational Triage Queue
                </h2>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-900 text-slate-500 tracking-wider font-extrabold text-[9px] uppercase">
                        <th className="py-3">Incident ID</th>
                        <th className="py-3">Timestamp</th>
                        <th className="py-3">Vector</th>
                        <th className="py-3">Source Vector</th>
                        <th className="py-3">Severity</th>
                        <th className="py-3">Status</th>
                        <th className="py-3 text-right">PDF Report</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-12 text-center text-slate-600 font-medium">
                            No active threat incidents reported in operational history.
                          </td>
                        </tr>
                      ) : (
                        incidents.map((inc) => (
                          <tr 
                            key={inc.id} 
                            onClick={() => setSelectedId(inc.id)}
                            className={`border-b border-slate-900/40 hover:bg-slate-900/30 cursor-pointer transition-all duration-200 relative ${selectedId === inc.id ? "bg-slate-900/50 border-l-2 border-l-cyan-500 shadow-inner" : ""}`}
                          >
                            <td className="py-3.5 font-mono text-slate-300 font-bold">{inc.id.slice(0, 8)}...</td>
                            <td className="py-3.5 text-slate-400">{inc.timestamp.replace("T", " ").slice(0, 16)}</td>
                            <td className="py-3.5">
                              <span className="font-bold text-slate-200">{inc.vector_type}</span>
                            </td>
                            <td className="py-3.5 text-slate-300 truncate max-w-[155px]" title={inc.target_input}>
                              {inc.target_input}
                            </td>
                            <td className="py-3.5">
                              <span className={`px-2 py-0.5 rounded border text-[9px] font-black uppercase ${getSeverityStyle(inc.severity)}`}>
                                {inc.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-3.5">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase ${getStatusBadge(inc.status)}`}>
                                {inc.status}
                              </span>
                            </td>
                            <td className="py-3.5 text-right">
                              <button 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  triggerReportDownload(inc.id);
                                }}
                                disabled={inc.status === "PENDING"}
                                className="p-1.5 bg-slate-900 border border-slate-800 hover:border-slate-705 hover:bg-slate-800 rounded text-slate-300 transition-all duration-200 disabled:opacity-30 active:scale-90"
                                title="Download Report"
                              >
                                <Download className="h-3.5 w-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
              
              <div className="text-[9px] text-slate-650 mt-4 text-center border-t border-slate-900/60 pt-3 flex items-center justify-center gap-1.5 uppercase font-bold tracking-wider">
                <Database className="h-3 w-3 text-cyan-500" /> Connection: Local PostgreSQL Database Persistent Store
              </div>
            </div>

          </div>

          {/* Right Column: Detailed Drilldown & Analytics Charts */}
          <div className="flex flex-col gap-6 h-full justify-between">
            
            {/* Detailed Incident Profile Panel */}
            <div className="bg-gradient-to-br from-slate-900/60 to-slate-950/60 backdrop-blur-xl border border-slate-900 rounded-xl p-5 min-h-[380px] flex flex-col justify-between shadow-2xl">
              {loadingDetail ? (
                <div className="flex-1 flex flex-col items-center justify-center py-24 text-slate-500 gap-2">
                  <RefreshCw className="h-6 w-6 animate-spin text-cyan-500" />
                  <span className="text-[10px] font-bold tracking-wider uppercase">Syncing telemetry data...</span>
                </div>
              ) : selectedIncident ? (
                <div className="flex flex-col h-full justify-between">
                  <div>
                    <div className="flex items-center justify-between border-b border-slate-900 pb-3 mb-4">
                      <div>
                        <h3 className="font-extrabold text-[10px] tracking-widest text-slate-500 uppercase">Incident Profile</h3>
                        <span className="font-mono text-[9px] text-slate-600">{selectedIncident.id}</span>
                      </div>
                      {selectedIncident.status === "PHISHING" && <Skull className="h-5 w-5 text-rose-500 animate-bounce" />}
                    </div>

                    {/* Threat Score Progress bar */}
                    <div className="mb-5 bg-slate-955 border border-slate-900 rounded-xl p-3.5 shadow-inner">
                      <div className="flex justify-between text-[10px] font-extrabold tracking-wider uppercase mb-1.5">
                        <span className="text-slate-550">Threat Score</span>
                        <span className={selectedIncident.status === "PHISHING" ? "text-rose-400" : selectedIncident.status === "SUSPICIOUS" ? "text-amber-400" : "text-emerald-400"}>
                          {selectedIncident.threat_score}
                        </span>
                      </div>
                      <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
                        <div 
                          className={`h-full transition-all duration-1000 ${selectedIncident.status === "PHISHING" ? "bg-gradient-to-r from-rose-600 to-rose-400" : selectedIncident.status === "SUSPICIOUS" ? "bg-gradient-to-r from-amber-600 to-amber-400" : "bg-gradient-to-r from-emerald-600 to-emerald-400"}`} 
                          style={{ width: `${Math.min((selectedIncident.threat_score / 12) * 100, 100)}%` }}
                        ></div>
                      </div>
                    </div>

                    {/* Operational fields */}
                    <div className="grid grid-cols-2 gap-4 text-[10px] mb-5 bg-slate-950/60 p-3.5 rounded-lg border border-slate-900/60 shadow-inner">
                      <div>
                        <span className="text-slate-550 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Ingest Vector</span>
                        <span className="font-bold text-slate-200">{selectedIncident.vector_type}</span>
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
                        <span className="text-slate-555 block uppercase font-bold text-[9px] tracking-wider mb-0.5">Time Logged</span>
                        <span className="font-semibold text-slate-300">{selectedIncident.timestamp}</span>
                      </div>
                    </div>

                    {/* Evidence List */}
                    <div className="mb-5">
                      <h4 className="text-[10px] font-extrabold text-slate-500 tracking-widest uppercase mb-2">Indicators of Compromise</h4>
                      <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1">
                        {selectedIncident.evidences.length === 0 ? (
                          <div className="text-xs text-slate-550 italic flex items-center gap-1.5 py-1">
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" /> Incident safe. No IoC flags.
                          </div>
                        ) : (
                          selectedIncident.evidences.map((ev, i) => (
                            <div key={i} className="bg-slate-950/80 border border-slate-900 rounded-lg p-2.5 text-[10px] leading-relaxed shadow-sm">
                              <span className="font-bold text-slate-400 block mb-0.5 text-[9px] uppercase tracking-wider">{ev.key}</span>
                              <span className="text-slate-300">{ev.value}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    {/* Remediations */}
                    <div className="mb-6">
                      <h4 className="text-[10px] font-extrabold text-slate-500 tracking-widest uppercase mb-2">SOC Remediations</h4>
                      <ul className="list-none text-[10px] text-slate-300 flex flex-col gap-2">
                        {selectedIncident.remediations.map((rem, i) => (
                          <li key={i} className="flex gap-2 items-start bg-slate-955/40 p-2.5 rounded-lg border border-slate-900/60 shadow-sm leading-relaxed">
                            {selectedIncident.status === "PHISHING" ? (
                              <AlertCircle className="h-4 w-4 text-rose-500 shrink-0 mt-0.5" />
                            ) : (
                              <Check className="h-4 w-4 text-emerald-500 shrink-0 mt-0.5" />
                            )}
                            <span>{rem}</span>
                          </li>
                        ))}
                        {selectedIncident.remediations.length === 0 && (
                          <li className="text-xs text-slate-550 italic flex items-center gap-1.5 py-1">
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" /> Incident safe. No containment required.
                          </li>
                        )}
                      </ul>
                    </div>
                  </div>

                  <button 
                    onClick={() => triggerReportDownload(selectedIncident.id)}
                    disabled={selectedIncident.status === "PENDING"}
                    className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-slate-100 font-extrabold text-[10px] tracking-widest py-3 rounded-lg flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 mt-auto shadow-lg shadow-emerald-950/20 active:scale-95"
                  >
                    <Download className="h-4 w-4" /> DOWNLOAD INCIDENT REPORT (PDF)
                  </button>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-550 py-24 border border-dashed border-slate-900 rounded-xl bg-slate-950/40">
                  <FileSearch className="h-10 w-10 text-slate-750 mb-2" />
                  <span className="text-[10px] font-extrabold tracking-wider uppercase text-slate-400 text-center px-4 leading-relaxed">Select an incident from triage feed to display tactical telemetry.</span>
                </div>
              )}
            </div>

          {/* Operational Metrics */}
          <div className="bg-gradient-to-br from-slate-900/60 to-slate-950/60 backdrop-blur-xl border border-slate-900 rounded-xl p-5 shadow-2xl">
            <h2 className="text-[10px] font-extrabold tracking-widest text-slate-500 uppercase mb-4 flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-cyan-400" /> Threat Analytics
            </h2>

            <div className="flex flex-col gap-5">
              {/* Pie Chart */}
              {statusChartData.length > 0 ? (
                <div>
                  <h4 className="text-[9px] font-extrabold text-slate-550 mb-2 uppercase tracking-widest">Classification Ratios</h4>
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
                    <div className="flex-1 text-[10px] pl-4 flex flex-col gap-2 font-semibold">
                      {statusChartData.map((d, i) => (
                        <div key={i} className="flex items-center justify-between">
                          <span className="flex items-center gap-1.5 text-slate-400">
                            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }}></span>
                            {d.name}
                          </span>
                          <span className="font-extrabold text-slate-200">{d.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-[10px] text-slate-550 italic text-center py-4">Threat ratio data pending.</div>
              )}

              {/* Bar Chart */}
              <div>
                <h4 className="text-[9px] font-extrabold text-slate-550 mb-2 uppercase tracking-widest">Scan Channels</h4>
                <div className="h-[125px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={vectorChartData} margin={{ top: 5, right: 5, left: -28, bottom: 5 }}>
                      <XAxis dataKey="name" stroke="#475569" fontSize={9} tickLine={false} />
                      <YAxis stroke="#475569" fontSize={9} tickLine={false} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: "#020617", border: "1px solid #1E293B", fontSize: 9 }}
                        cursor={{ fill: "rgba(6, 182, 212, 0.03)" }}
                      />
                      <Bar 
                        dataKey="scans" 
                        fill="#06b6d4" 
                        radius={[4, 4, 0, 0]}
                        isAnimationActive={false}
                      >
                        {vectorChartData.map((entry, index) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={entry.name === "URL" ? "#06b6d4" : entry.name === "Email" ? "#6366f1" : entry.name === "Log" ? "#10b981" : "#f43f5e"} 
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
    </div>
  );
}

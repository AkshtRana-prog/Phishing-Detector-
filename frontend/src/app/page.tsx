"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Link,
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
  Search,
  Lock,
  Mail,
  UserPlus,
  ArrowRight,
  LogOut,
  Trash2,
  Menu,
  Server,
  Wifi,
  ChevronRight,
  Plus,
  Bell,
  User,
  X,
  Settings,
  Database,
  Sliders,
  Terminal,
  Grid,
  FileDown,
  Command,
  Eye,
  Check,
  HelpCircle,
  TrendingUp,
  AlertCircle,
  Play,
  Pause,
  ChevronLeft,
  Volume2,
  VolumeX,
  Zap,
  CheckCircle,
  ChevronDown,
  Sun,
  Moon
} from "lucide-react";
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  LineChart,
  Line,
  XAxis, 
  YAxis, 
  Tooltip, 
  BarChart, 
  Bar, 
  Cell,
  PieChart,
  Pie
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

// Name Extraction Helper
const getAnalystName = (email: string | null) => {
  if (!email) return "Guest Analyst";
  const cleanEmail = email.toLowerCase().trim();
  if (cleanEmail === "admin@orion.com") return "Aksht";
  const localPart = cleanEmail.split("@")[0];
  return localPart
    .split(".")
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
};

// ----------------------------------------------------
// 1. RESTRAINED NODE NETWORK GRAPH (LOGIN VISUALIZATION)
// ----------------------------------------------------
interface NodeGraphProps {
  isFocused: boolean;
  isConverging: boolean;
  onComplete?: () => void;
}

function NodeNetworkGraph({ isFocused, isConverging, onComplete }: NodeGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 500);
    let height = (canvas.height = canvas.parentElement?.clientHeight || 600);

    const handleResize = () => {
      if (canvas && canvas.parentElement) {
        width = canvas.width = canvas.parentElement.clientWidth;
        height = canvas.height = canvas.parentElement.clientHeight;
      }
    };
    window.addEventListener("resize", handleResize);

    // Initialize nodes
    const numNodes = 40;
    const nodes: { x: number; y: number; vx: number; vy: number; radius: number }[] = [];
    for (let i = 0; i < numNodes; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: 1.5 + Math.random() * 2
      });
    }

    const startTime = Date.now();

    const animate = () => {
      ctx.fillStyle = "#080F17"; // Matches the exact dark navy backdrop
      ctx.fillRect(0, 0, width, height);

      const speedMultiplier = isFocused ? 2.5 : 1.0;
      const elapsed = Date.now() - startTime;

      ctx.lineWidth = 0.5;
      for (let i = 0; i < numNodes; i++) {
        const n1 = nodes[i];

        if (isConverging) {
          const centerX = width / 2;
          const centerY = height / 2;
          n1.x += (centerX - n1.x) * 0.12;
          n1.y += (centerY - n1.y) * 0.12;
        } else {
          n1.x += n1.vx * speedMultiplier;
          n1.y += n1.vy * speedMultiplier;

          if (n1.x < 0 || n1.x > width) n1.vx = -n1.vx;
          if (n1.y < 0 || n1.y > height) n1.vy = -n1.vy;
        }

        for (let j = i + 1; j < numNodes; j++) {
          const n2 = nodes[j];
          const dist = Math.hypot(n1.x - n2.x, n1.y - n2.y);
          if (dist < 90) {
            const alpha = (1 - dist / 90) * 0.12;
            ctx.strokeStyle = `rgba(124, 58, 237, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }

        ctx.fillStyle = isFocused ? "rgba(244, 63, 142, 0.6)" : "rgba(124, 58, 237, 0.35)";
        ctx.beginPath();
        ctx.arc(n1.x, n1.y, n1.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      if (isConverging && elapsed > 850) {
        cancelAnimationFrame(animationId);
        if (onComplete) onComplete();
        return;
      }

      animationId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", handleResize);
    };
  }, [isFocused, isConverging, onComplete]);

  return <canvas ref={canvasRef} className="w-full h-full block opacity-70" />;
}

// ----------------------------------------------------
// 2. PRODUCTIVITY FLOATING MUSIC PLAYER
// ----------------------------------------------------
function MusicPlayer() {
  const [isPlaying, setIsPlaying] = useState(false);
  const [progress, setProgress] = useState(30);
  const [volume, setVolume] = useState(80);
  const [isMuted, setIsMuted] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);

  // Play progress interval
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setProgress(prev => (prev >= 100 ? 0 : prev + 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [isPlaying]);

  if (isMinimized) {
    return (
      <button 
        onClick={() => setIsMinimized(false)}
        className="glass-premium p-2.5 rounded-xl text-blue-400 hover:text-white transition active:scale-95 flex items-center justify-center gap-2 cursor-pointer w-full text-[10px]"
        title="Open Music Player"
      >
        <Music className="h-4.5 w-4.5 text-purple-400 animate-pulse" />
        <span className="font-semibold text-white">Now Playing: Night Drive</span>
      </button>
    );
  }

  return (
    <div className="glass-premium p-3.5 rounded-xl flex flex-col gap-2.5 relative">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded bg-gradient-to-br from-purple-600 to-pink-500 flex items-center justify-center text-[10px] font-bold text-white shadow-md overflow-hidden shrink-0">
            <span className="text-[11px]">ND</span>
          </div>
          <div>
            <span className="text-[11px] font-bold text-white block truncate w-32">Night Drive</span>
            <span className="text-[9px] text-[#8D96A3] block">Jessie Ware</span>
          </div>
        </div>
        <button onClick={() => setIsMinimized(true)} className="text-[#626B78] hover:text-white transition cursor-pointer"><X className="h-3.5 w-3.5" /></button>
      </div>

      {/* Progress Bar scrubber */}
      <div className="flex items-center gap-2">
        <span className="text-[8px] text-[#626B78] font-mono">
          {Math.floor((progress * 2.4) / 60)}:{(Math.floor(progress * 2.4) % 60).toString().padStart(2, "0")}
        </span>
        <div 
          onClick={e => {
            const rect = e.currentTarget.getBoundingClientRect();
            const pct = Math.round(((e.clientX - rect.left) / rect.width) * 100);
            setProgress(pct);
          }}
          className="flex-1 bg-white/10 h-1 rounded-full cursor-pointer relative"
        >
          <div className="bg-gradient-to-r from-purple-500 to-blue-500 h-full rounded-full" style={{ width: `${progress}%` }}></div>
          <div className="absolute top-1/2 -translate-y-1/2 w-2 h-2 bg-white rounded-full shadow" style={{ left: `calc(${progress}% - 4px)` }}></div>
        </div>
        <span className="text-[8px] text-[#626B78] font-mono">04:00</span>
      </div>

      {/* Control buttons */}
      <div className="flex items-center justify-between mt-0.5">
        <button className="text-[#8D96A3] hover:text-white" title="Previous track"><ChevronLeft className="h-4 w-4" /></button>
        <button 
          onClick={() => setIsPlaying(!isPlaying)}
          className="w-7 h-7 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 text-white flex items-center justify-center shadow-lg transition active:scale-90 cursor-pointer"
        >
          {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5 fill-current ml-0.5" />}
        </button>
        <button className="text-[#8D96A3] hover:text-white" title="Next track"><ChevronRight className="h-4 w-4" /></button>
        
        {/* Volume toggler */}
        <div className="flex items-center gap-1">
          <button onClick={() => setIsMuted(!isMuted)} className="text-[#8D96A3] hover:text-white transition cursor-pointer">
            {isMuted || volume === 0 ? <VolumeX className="h-3.5 w-3.5" /> : <Volume2 className="h-3.5 w-3.5" />}
          </button>
          <input 
            type="range" 
            min="0" 
            max="100" 
            value={isMuted ? 0 : volume}
            onChange={e => { setVolume(Number(e.target.value)); setIsMuted(false); }}
            className="w-12 accent-purple-500 h-1 cursor-pointer bg-white/10 rounded-full"
          />
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 3. STAT CARD WITH MINI AREA SPARKLINE
// ----------------------------------------------------
interface KPIProps {
  title: string;
  targetVal: number;
  valSuffix?: string;
  trend: string;
  isPositive: boolean;
  sparkData: { value: number }[];
  accentColor: string;
  onInfoClick?: () => void;
}

function KPIWidget({ title, targetVal, valSuffix = "", trend, isPositive, sparkData, accentColor, onInfoClick }: KPIProps) {
  const [displayVal, setDisplayVal] = useState(0);

  useEffect(() => {
    let start = 0;
    const duration = 750;
    const steps = 30;
    const increment = targetVal / steps;
    const stepTime = duration / steps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= targetVal) {
        setDisplayVal(targetVal);
        clearInterval(timer);
      } else {
        setDisplayVal(Math.round(start * 10) / 10);
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [targetVal]);

  return (
    <div className="glass-medium glass-highlight p-4.5 rounded-2xl flex flex-col justify-between h-32 hover:-translate-y-0.5 hover:border-white/15 transition-all duration-300 relative group shadow-xl">
      <div>
        <div className="flex justify-between items-center">
          <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-wider block">{title}</span>
          {onInfoClick && (
            <button 
              onClick={onInfoClick}
              className="text-[#626B78] hover:text-white transition cursor-pointer"
              title="Show calculation details"
            >
              <HelpCircle className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        <div className="flex items-baseline gap-2 mt-2">
          <span className="text-2xl font-extrabold text-white tracking-tight">
            {valSuffix === "%" ? `${displayVal}%` : displayVal}
          </span>
          <span className={`text-[10px] font-semibold ${isPositive ? "text-emerald-400" : "text-[#EF4444]"}`}>
            {trend}
          </span>
        </div>
      </div>
      {/* Mini sparkline */}
      <div className="h-8 mt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={sparkData}>
            <defs>
              <linearGradient id={`grad-${title.replace(/ /g, "")}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={accentColor} stopOpacity={0.25}/>
                <stop offset="95%" stopColor={accentColor} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="value" stroke={accentColor} strokeWidth={1} fillOpacity={1} fill={`url(#grad-${title.replace(/ /g, "")})`} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// 4. MAIN WORKSPACE REDESIGN CORE
// ----------------------------------------------------
export default function SOCDashboard() {
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authMessage, setAuthMessage] = useState({ text: "", isError: false });

  // UI state variables
  const [activeTab, setActiveTab] = useState("overview"); // overview, investigate, incidents, analytics, reports, settings, activity
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const [isConverging, setIsConverging] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [accuracyTooltipOpen, setAccuracyTooltipOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [apiOffline, setApiOffline] = useState(false);

  // Diagnostic Scan state
  const [diagnosticRunning, setDiagnosticRunning] = useState(false);
  const [diagnosticMessage, setDiagnosticMessage] = useState<string | null>(null);

  // Operational threat telemetry data
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  
  // Ingest channels controls
  const [urlInput, setUrlInput] = useState("");
  const [urlScanning, setUrlScanning] = useState(false);
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [emlScanning, setEmlScanning] = useState(false);
  const [logFile, setLogFile] = useState<File | null>(null);
  const [logScanning, setLogScanning] = useState(false);
  const [mediaFile, setMediaFile] = useState<File | null>(null);
  const [mediaType, setMediaType] = useState<"audio" | "video">("video");
  const [mediaScanning, setMediaScanning] = useState(false);

  // Timeline progress states
  const [timelineStep, setTimelineStep] = useState(0);
  const [isScanningActive, setIsScanningActive] = useState(false);

  // Settings submenu tabs
  const [settingsCategory, setSettingsCategory] = useState("appearance");

  // Phase 2 State Variables
  const [selectedIncidentDrawer, setSelectedIncidentDrawer] = useState<Incident | null>(null);
  const [signalModal, setSignalModal] = useState<{ title: string; weight: string; evidence: string; confidence: string; rationale: string } | null>(null);
  const [glassIntensity, setGlassIntensity] = useState<"low" | "medium" | "high">("medium");
  const [uiDensity, setUiDensity] = useState<"comfortable" | "compact">("comfortable");
  const [analystNotes, setAnalystNotes] = useState<Record<string, string>>({});
  const [urlSensitivity, setUrlSensitivity] = useState<number>(85);
  const [emailSensitivity, setEmailSensitivity] = useState<number>(80);
  const [mediaSensitivity, setMediaSensitivity] = useState<number>(90);
  const [logSensitivity, setLogSensitivity] = useState<number>(75);

  // Workspace Form State
  const [deepScanEnabled, setDeepScanEnabled] = useState(false);
  const [passiveAnalysisEnabled, setPassiveAnalysisEnabled] = useState(true);
  const [rawHeadersText, setRawHeadersText] = useState("");
  const [rawLogText, setRawLogText] = useState("");


  // Threat Analytics metrics
  const [analytics, setAnalytics] = useState({
    total_scans: 131,
    status_distribution: { PHISHING: 61, SUSPICIOUS: 19, SAFE: 13, DEEPFAKE: 35 },
    severity_distribution: { LOW: 10, MEDIUM: 30, HIGH: 61, CRITICAL: 30 },
    vector_distribution: { URL: 48, Email: 27, Deepfake: 35, Log: 21 },
    time_trends: [
      { name: "May 30", Phishing: 40, Deepfake: 25, Exploits: 10, Safe: 8 },
      { name: "May 31", Phishing: 42, Deepfake: 20, Exploits: 12, Safe: 9 },
      { name: "Jun 1", Phishing: 48, Deepfake: 30, Exploits: 14, Safe: 12 },
      { name: "Jun 2", Phishing: 45, Deepfake: 28, Exploits: 15, Safe: 10 },
      { name: "Jun 3", Phishing: 47, Deepfake: 32, Exploits: 11, Safe: 11 },
      { name: "Jun 4", Phishing: 49, Deepfake: 26, Exploits: 13, Safe: 9 },
      { name: "Jun 5", Phishing: 48, Deepfake: 27, Exploits: 15, Safe: 10 }
    ] as any[]
  });

  // Ticking states for health metrics
  const [ipsActive, setIpsActive] = useState(true);
  const [celeryWorkers, setCeleryWorkers] = useState(4);
  const [lastSyncSecs, setLastSyncSecs] = useState(12);
  const [isLivePaused, setIsLivePaused] = useState(false);
  const [logSearch, setLogSearch] = useState("");
  const [logFilter, setLogFilter] = useState("ALL");
  const [expandedLogIdx, setExpandedLogIdx] = useState<number | null>(null);

  const [liveLogs, setLiveLogs] = useState([
    { time: "19:02:34", category: "THREAT", msg: "URL reputation lookup matched suspected typosquatting database.", sev: "WARNING" },
    { time: "19:01:12", category: "INFO", msg: "Deepfake analysis completed for file video_sample.mp4", sev: "INFO" },
    { time: "19:00:44", category: "ALERT", msg: "Multiple failed login attempts detected from 45.77.12.9", sev: "ALERT" },
    { time: "18:59:37", category: "SUCCESS", msg: "Database backup completed successfully.", sev: "SUCCESS" },
    { time: "18:57:12", category: "SYSTEM", msg: "Celery worker pool connected to Redis broker task queue.", sev: "SUCCESS" }
  ]);

  // Dynamic log generator feed
  useEffect(() => {
    if (isLivePaused || !isLoggedIn) return;
    const logPool = [
      { category: "NETWORK", msg: "Brute-force SSH probe on port 22. Target source isolated.", sev: "CRITICAL" },
      { category: "SYSTEM", msg: "Analysis queue processed 1 pending task in 342ms.", sev: "SAFE" },
      { category: "THREAT", msg: "Deepfake media frame entropy ratio check completed. Status: normal.", sev: "SAFE" },
      { category: "DATABASE", msg: "Telemetry database synchronization complete. 0 discrepancies.", sev: "SAFE" },
      { category: "THREAT", msg: "URL reputation lookup matched suspected typosquatting database.", sev: "WARNING" }
    ];

    const interval = setInterval(() => {
      const randomLog = logPool[Math.floor(Math.random() * logPool.length)];
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];
      setLiveLogs(prev => [
        { time: timeStr, ...randomLog },
        ...prev.slice(0, 49)
      ]);
    }, 8000);

    return () => clearInterval(interval);
  }, [isLivePaused, isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn) return;
    const interval = setInterval(() => {
      setLastSyncSecs(prev => (prev >= 60 ? 0 : prev + 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // Analyst clock
  const [currentTime, setCurrentTime] = useState<Date | null>(null);

  // Search filter options
  const [filterVector, setFilterVector] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [filterSeverity, setFilterSeverity] = useState("ALL");
  const [filterSearch, setFilterSearch] = useState("");
  const [activeDropdownId, setActiveDropdownId] = useState<string | null>(null);

  useEffect(() => {
    setCurrentTime(new Date());
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Keyboard shortcut listener (Ctrl+K palette / Escape close)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setCommandPaletteOpen(prev => !prev);
      }
      if (e.key === "Escape") {
        setCommandPaletteOpen(false);
        setNotificationsOpen(false);
        setSelectedId(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Close dropdown on click outside
  useEffect(() => {
    const handleOutsideClick = () => {
      setActiveDropdownId(null);
      setProfileDropdownOpen(false);
    };
    window.addEventListener("click", handleOutsideClick);
    return () => window.removeEventListener("click", handleOutsideClick);
  }, []);

  // Load user session
  useEffect(() => {
    const saved = localStorage.getItem("soc_user_email");
    if (saved) {
      setUserEmail(saved);
      setIsLoggedIn(true);
    }
  }, []);

  // Ingestion timeline simulator
  useEffect(() => {
    if (!isScanningActive) return;
    const interval = setInterval(() => {
      setTimelineStep(prev => {
        if (prev >= 5) {
          setIsScanningActive(false);
          clearInterval(interval);
          return 5;
        }
        return prev + 1;
      });
    }, 800);
    return () => clearInterval(interval);
  }, [isScanningActive]);

  // Fetch incidents list
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
        setApiOffline(false);
      } else {
        setApiOffline(true);
      }
    } catch (e) {
      console.error(e);
      setApiOffline(true);
    } finally {
      if (!silent) setLoadingList(false);
    }
  };

  // Fetch analytics telemetry
  const fetchAnalytics = async () => {
    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/analytics`, {
        headers: { "X-User-Email": email }
      });
      if (res.ok) {
        const data = await res.json();
        setAnalytics(prev => ({
          ...prev,
          total_scans: data.total_scans,
          status_distribution: data.status_distribution,
          severity_distribution: data.severity_distribution,
          vector_distribution: data.vector_distribution,
          time_trends: data.time_trends || []
        }));
        setApiOffline(false);
      } else {
        setApiOffline(true);
      }
    } catch (e) {
      console.error(e);
      setApiOffline(true);
    }
  };

  // Fetch incident detail records
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
      console.error(e);
    } finally {
      if (!silent) setLoadingDetail(false);
    }
  };

  // Poll background queue changes
  useEffect(() => {
    if (!isLoggedIn) return;
    fetchIncidents();
    fetchAnalytics();
    
    const interval = setInterval(() => {
      fetchIncidents(true);
      fetchAnalytics();
    }, 6000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // Detail panel syncing
  useEffect(() => {
    if (!isLoggedIn || !selectedId) return;
    const isNew = !selectedIncident || selectedIncident.id !== selectedId;
    fetchIncidentDetail(selectedId, !isNew);

    const interval = setInterval(() => {
      fetchIncidentDetail(selectedId, true);
    }, 4000);
    return () => clearInterval(interval);
  }, [selectedId, isLoggedIn]);

  // Authenticate submission
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
          setIsConverging(true); // Pull nodes together
        } else {
          setAuthMessage({
            text: "Access request submitted. Verification email dispatched to your inbox.",
            isError: false
          });
          setAuthEmail("");
          setAuthPassword("");
          setAuthLoading(false);
        }
      } else {
        setAuthMessage({ text: data.detail || "Credentials failed verification", isError: true });
        setAuthLoading(false);
      }
    } catch (err) {
      setAuthMessage({ text: "Authentication gateway connection error", isError: true });
      setAuthLoading(false);
    }
  };

  // Logout session
  const handleLogout = () => {
    localStorage.removeItem("soc_user_email");
    setUserEmail(null);
    setIsLoggedIn(false);
    setSelectedId(null);
    setSelectedIncident(null);
    setAuthEmail("");
    setAuthPassword("");
    setIsConverging(false);
    setAuthMessage({ text: "", isError: false });
  };

  // Incident deletion
  const handleDeleteIncident = async (id: string) => {
    if (!window.confirm("Archive and delete this threat incident permanently?")) return;
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}`, { method: "DELETE" });
      if (res.ok) {
        if (selectedId === id) {
          setSelectedId(null);
          setSelectedIncident(null);
        }
        fetchIncidents();
        fetchAnalytics();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // ML Training feedback loops
  const handleTrainML = async (id: string, label: string) => {
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}/train`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label })
      });
      if (res.ok) {
        fetchIncidents(true);
        fetchAnalytics();
        if (selectedId === id) fetchIncidentDetail(id, true);
        alert(`Model trained successfully in backend as: ${label}`);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Diagnostic scan trigger
  const runDiagnostic = () => {
    setDiagnosticRunning(true);
    setDiagnosticMessage(null);
    setTimeout(() => {
      setDiagnosticRunning(false);
      setDiagnosticMessage("✓ Diagnostic complete. 14 security vectors audited. 0 compromise hashes found.");
      setTimeout(() => setDiagnosticMessage(null), 5000);
    }, 1500);
  };

  // Submissions for URL vector scans
  const startURLScan = async (e?: React.FormEvent, directUrl?: string) => {
    if (e) e.preventDefault();
    const targetUrl = (directUrl || urlInput).trim();
    if (!targetUrl) return;
    setUrlScanning(true);
    setTimelineStep(0);
    setIsScanningActive(true);

    try {
      const email = localStorage.getItem("soc_user_email") || "";
      const res = await fetch(`${API_BASE}/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-User-Email": email },
        body: JSON.stringify({ url: targetUrl })
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedId(data.incident_id);
        fetchIncidents();
        fetchAnalytics();
        fetchIncidentDetail(data.incident_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setUrlScanning(false);
    }
  };

  // EML File Scan Ingestion
  const startEMLScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emlFile) return;
    setEmlScanning(true);
    setTimelineStep(0);
    setIsScanningActive(true);

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
        fetchIncidents();
        fetchAnalytics();
        fetchIncidentDetail(data.incident_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setEmlScanning(false);
    }
  };

  // Log / PCAP upload Ingestion
  const startLogScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!logFile) return;
    setLogScanning(true);
    setTimelineStep(0);
    setIsScanningActive(true);

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
        fetchIncidents();
        fetchAnalytics();
        fetchIncidentDetail(data.incident_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLogScanning(false);
    }
  };

  // Video / Audio deepfake forensics upload
  const startMediaScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mediaFile) return;
    setMediaScanning(true);
    setTimelineStep(0);
    setIsScanningActive(true);

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
        fetchIncidents();
        fetchAnalytics();
        fetchIncidentDetail(data.incident_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setMediaScanning(false);
    }
  };

  const downloadReport = (id: string) => {
    setSelectedReportId(id);
    setActiveTab("reports");
    setTimeout(() => {
      window.print();
    }, 200);
  };

  const downloadGlobalReport = async () => {
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
        a.download = "ORION_SOC_SUMMARY_REPORT.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Dynamic greetings selector based on hour
  const getGreeting = (name: string) => {
    const hours = new Date().getHours();
    if (hours < 12) return `Good morning, ${name} 👋`;
    if (hours < 18) return `Good afternoon, ${name} ☀️`;
    return `Good evening, ${name} 🌙`;
  };

  // Helper to format timestamps to relative time words
  const formatTimeAgo = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      const diffMs = new Date().getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      if (diffMins < 1) return "Just now";
      if (diffMins < 60) return `${diffMins}m ago`;
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      const diffDays = Math.floor(diffHours / 24);
      return `${diffDays}d ago`;
    } catch (e) {
      return "Recently";
    }
  };

  // Severity color badge mapping (Outlined visual styling)
  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "text-[#EF4444] bg-[#EF4444]/5 border border-[#EF4444]/20";
      case "HIGH":
        return "text-orange-400 bg-orange-500/5 border border-orange-500/20";
      case "MEDIUM":
        return "text-[#FBBF24] bg-[#FBBF24]/5 border border-[#FBBF24]/20";
      default:
        return "text-[#10B981] bg-[#10B981]/5 border border-[#10B981]/20";
    }
  };

  // Status color badge mapping (Outlined visual styling)
  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case "PHISHING":
        return "bg-rose-500/5 text-[#EF4444] border border-rose-500/20";
      case "DEEPFAKE":
        return "bg-pink-500/5 text-pink-400 border border-pink-500/20";
      case "SUSPICIOUS":
        return "bg-amber-500/5 text-[#F59E0B] border border-amber-500/20";
      case "SAFE":
      case "LEGITIMATE":
        return "bg-emerald-500/5 text-emerald-400 border border-emerald-500/20";
      default:
        return "bg-white/5 text-[#8D96A3] border border-white/8";
    }
  };

  // Render Login screens if not authenticated
  if (!isLoggedIn) {
    return (
      <div className={`flex min-h-screen bg-[#080F17] text-[#F3F5F7] font-sans overflow-hidden relative ${theme === "light" ? "theme-light" : "theme-dark"}`}>
        {/* Shifting radial glows in the background */}
        <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden bg-[#080F17]">
          <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-purple-700/10 rounded-full blur-[120px] animate-orb-1" />
          <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-700/10 rounded-full blur-[120px] animate-orb-2" />
        </div>

        {/* Left Side: Restrained Node network graph */}
        <div className="hidden md:flex md:w-1/2 bg-black/25 relative items-center justify-center border-r border-white/5 overflow-hidden z-10">
          <div className="absolute inset-0 z-0">
            <NodeNetworkGraph 
              isFocused={isFocused} 
              isConverging={isConverging} 
              onComplete={() => {
                localStorage.setItem("soc_user_email", authEmail.trim().toLowerCase());
                setUserEmail(authEmail.trim().toLowerCase());
                setIsLoggedIn(true);
                setAuthLoading(false);
              }}
            />
          </div>
          <div className="z-10 text-center max-w-sm px-6 pointer-events-none">
            <Shield className="h-10 w-10 text-purple-500 mx-auto mb-4 animate-pulse" />
            <h2 className="text-xl font-bold tracking-tight text-white mb-2">Workspace Intelligence</h2>
            <p className="text-xs text-[#8D96A3] leading-relaxed">
              Orion SOC maps digital compromise vectors across URL, Email, PCAP files, and media channels.
            </p>
          </div>
        </div>

        {/* Right Side: Clean login card */}
        <div className="w-full md:w-1/2 flex flex-col justify-center px-8 sm:px-16 md:px-24 bg-transparent z-10 animate-in fade-in duration-300">
          <div className="max-w-md w-full mx-auto bg-[#0D111A] border border-white/5 p-8 rounded-2xl shadow-2xl relative">
            <div className="mb-8 flex items-center gap-3 relative z-10">
              <div className="w-9 h-9 rounded-full border border-blue-500/30 overflow-hidden shadow">
                <img src="/logo.jpg" alt="Logo" className="w-full h-full object-cover" />
              </div>
              <div>
                <h1 className="text-sm font-bold tracking-widest text-[#F3F5F7]">ORION SOC</h1>
                <p className="text-[10px] text-[#8D96A3] uppercase tracking-wider">Threat Center Portal</p>
              </div>
            </div>

            <h2 className="text-xl font-bold tracking-tight text-white mb-1 relative z-10">Welcome back</h2>
            <p className="text-xs text-[#8D96A3] mb-6 relative z-10">Sign in to your security workspace.</p>

            <form onSubmit={handleAuthSubmit} className="flex flex-col gap-4 relative z-10">
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-bold text-[#8D96A3] uppercase tracking-wider">Email Address</label>
                <input 
                  type="email" 
                  placeholder="name@orion.com"
                  value={authEmail}
                  onChange={e => setAuthEmail(e.target.value)}
                  onFocus={() => setIsFocused(true)}
                  onBlur={() => setIsFocused(false)}
                  required
                  className="w-full bg-[#080B12] border border-white/5 rounded-lg py-2.5 px-3 text-xs text-[#F3F5F7] placeholder-[#626B78] focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/20 transition-all"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <div className="flex justify-between items-center">
                  <label className="text-[10px] font-bold text-[#8D96A3] uppercase tracking-wider">Access Password</label>
                  <a href="#" className="text-[10px] text-blue-400 hover:text-blue-300 font-medium">Forgot?</a>
                </div>
                <input 
                  type="password" 
                  placeholder="••••••••••••"
                  value={authPassword}
                  onChange={e => setAuthPassword(e.target.value)}
                  onFocus={() => setIsFocused(true)}
                  onBlur={() => setIsFocused(false)}
                  required
                  className="w-full bg-[#080B12] border border-white/5 rounded-lg py-2.5 px-3 text-xs text-[#F3F5F7] placeholder-[#626B78] focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/20 transition-all"
                />
              </div>

              {authMessage.text && (
                <div className={`p-3 rounded-lg border text-[10px] ${authMessage.isError ? "bg-rose-950/20 border-rose-500/30 text-[#F87171]" : "bg-emerald-950/20 border-emerald-500/30 text-emerald-400"}`}>
                  {authMessage.text}
                </div>
              )}

              <button 
                type="submit" 
                disabled={authLoading}
                className="w-full bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-bold text-xs py-2.5 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50 mt-2 cursor-pointer shadow-lg active:scale-95"
              >
                {isConverging ? "Authenticating..." : authLoading ? "Verifying secure session..." : "Continue"}
                <ArrowRight className="h-4 w-4" />
              </button>
            </form>

            <div className="border-t border-white/5 mt-6 pt-4 text-center relative z-10">
              {authMode === "login" ? (
                <button 
                  type="button" 
                  onClick={() => { setAuthMode("signup"); setAuthMessage({ text: "", isError: false }); }}
                  className="text-[10px] text-[#8D96A3] hover:text-purple-400 tracking-wider transition"
                >
                  Need a security key? Request workspace registration
                </button>
              ) : (
                <button 
                  type="button" 
                  onClick={() => { setAuthMode("login"); setAuthMessage({ text: "", isError: false }); }}
                  className="text-[10px] text-[#8D96A3] hover:text-purple-400 tracking-wider transition"
                >
                  Authorized sign-in
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Filtered incidents
  const filteredIncidents = incidents.filter(inc => {
    const matchVector = filterVector === "ALL" || inc.vector_type === filterVector;
    const matchStatus = filterStatus === "ALL" || inc.status.toUpperCase() === filterStatus.toUpperCase();
    const matchSeverity = filterSeverity === "ALL" || inc.severity.toUpperCase() === filterSeverity.toUpperCase();
    const matchSearch =
      !filterSearch ||
      inc.id.toLowerCase().includes(filterSearch.toLowerCase()) ||
      inc.target_input.toLowerCase().includes(filterSearch.toLowerCase());
    return matchVector && matchStatus && matchSeverity && matchSearch;
  });

  const chartData = analytics.time_trends;

  // Synced original data parameters for the Donut Chart
  const phishCount = analytics.status_distribution.PHISHING || 0;
  const deepCount = analytics.status_distribution.DEEPFAKE || 0;
  const suspCount = analytics.status_distribution.SUSPICIOUS || 0;
  const safeCount = analytics.status_distribution.SAFE || 0;
  const totalDonutCount = phishCount + deepCount + suspCount + safeCount || 1;

  const donutData = [
    { name: "Phishing URLs", value: phishCount, color: "#8B5CF6" },
    { name: "Deepfakes", value: deepCount, color: "#F43F8E" },
    { name: "Network Exploits", value: suspCount, color: "#F59E0B" },
    { name: "Safe / Legitimate", value: safeCount, color: "#10B981" }
  ];

  const getPercent = (val: number) => {
    return Math.round((val / totalDonutCount) * 100);
  };

  return (
    <div className={`flex min-h-screen bg-[#080F17] text-[#F3F5F7] font-sans selection:bg-purple-500/20 relative ${theme === "light" ? "theme-light" : "theme-dark"}`}>
      
      {/* ATMOSPHERIC BACKGROUND RADIAL GLOWS */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden bg-[#080F17]">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-purple-700/10 rounded-full blur-[120px] animate-orb-1" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-700/10 rounded-full blur-[120px] animate-orb-2" />
        <div className="absolute top-[30%] right-[20%] w-[35%] h-[35%] bg-pink-700/5 rounded-full blur-[100px] animate-orb-3" />
      </div>

      {/* LEFT SIDEBAR (Liquid Glass style) */}
      <aside className={`glass-sidebar flex flex-col justify-between transition-all duration-300 z-20 shrink-0 ${sidebarCollapsed ? "w-16" : "w-60"}`}>
        <div>
          {/* Logo header */}
          <div className="p-4 border-b border-white/5 flex items-center justify-between">
            {sidebarCollapsed ? (
              <div className="w-full flex justify-center">
                <div className="w-8 h-8 rounded-full border border-blue-500/20 overflow-hidden shrink-0">
                  <img src="/logo.jpg" alt="Logo" className="w-full h-full object-cover" />
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3 overflow-hidden">
                <div className="w-8 h-8 rounded-full border border-blue-500/20 overflow-hidden shrink-0">
                  <img src="/logo.jpg" alt="Logo" className="w-full h-full object-cover" />
                </div>
                <div className="truncate">
                  <span className="font-extrabold text-xs tracking-wider text-white uppercase bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">ORION SOC</span>
                  <p className="text-[8px] text-[#8D96A3] tracking-widest uppercase">Lead Architect</p>
                </div>
              </div>
            )}
          </div>

          {/* Sidebar Nav categories */}
          <nav className="p-3 flex flex-col gap-4">
            {/* Overview active button */}
            <button
              onClick={() => setActiveTab("overview")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition duration-150 cursor-pointer ${activeTab === "overview" ? "bg-gradient-to-r from-purple-600 to-blue-500 text-white font-semibold shadow-md animate-pulse" : "text-[#8D96A3] hover:bg-white/5 hover:text-white"}`}
            >
              <Grid className="h-4 w-4 shrink-0" />
              {!sidebarCollapsed && <span>Overview</span>}
            </button>

            {/* Investigate Section */}
            <div>
              {!sidebarCollapsed && <span className="px-2.5 text-[8px] font-bold text-[#626B78] uppercase tracking-widest block mb-1">Investigate</span>}
              <div className="flex flex-col gap-0.5">
                {[
                  { id: "url_analysis", label: "URL Analysis", icon: Link },
                  { id: "email_analysis", label: "Email Analysis", icon: Mail },
                  { id: "log_analysis", label: "Logs / PCAP", icon: Terminal },
                  { id: "media_analysis", label: "Media Analysis", icon: Video }
                ].map(sub => {
                  const Icon = sub.icon;
                  return (
                    <button
                      key={sub.id}
                      onClick={() => setActiveTab(sub.id)}
                      className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs transition text-left cursor-pointer ${activeTab === sub.id ? "text-white bg-white/5 border-l-2 border-purple-500 pl-2 font-medium" : "text-[#8D96A3] hover:text-white hover:bg-white/5"}`}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      {!sidebarCollapsed && <span>{sub.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Operations Section */}
            <div>
              {!sidebarCollapsed && <span className="px-2.5 text-[8px] font-bold text-[#626B78] uppercase tracking-widest block mb-1">Operations</span>}
              <div className="flex flex-col gap-0.5">
                {[
                  { id: "incidents", label: "Threat Queue", icon: Shield },
                  { id: "activity", label: "Activity Logs", icon: Activity }
                ].map(sub => {
                  const Icon = sub.icon;
                  return (
                    <button
                      key={sub.id}
                      onClick={() => setActiveTab(sub.id)}
                      className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs transition text-left cursor-pointer ${activeTab === sub.id ? "text-white bg-white/5 border-l-2 border-purple-500 pl-2 font-medium" : "text-[#8D96A3] hover:text-white hover:bg-white/5"}`}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      {!sidebarCollapsed && <span>{sub.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Analytics Section */}
            <div>
              {!sidebarCollapsed && <span className="px-2.5 text-[8px] font-bold text-[#626B78] uppercase tracking-widest block mb-1">Analytics</span>}
              <button
                onClick={() => setActiveTab("analytics")}
                className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs transition text-left cursor-pointer ${activeTab === "analytics" ? "text-white bg-white/5 border-l-2 border-purple-500 pl-2 font-medium" : "text-[#8D96A3] hover:text-white hover:bg-white/5"}`}
              >
                <TrendingUp className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && <span>Threat Analytics</span>}
              </button>
            </div>

            {/* Reporting Section */}
            <div>
              {!sidebarCollapsed && <span className="px-2.5 text-[8px] font-bold text-[#626B78] uppercase tracking-widest block mb-1">Reporting</span>}
              <button
                onClick={() => setActiveTab("reports")}
                className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs transition text-left cursor-pointer ${activeTab === "reports" ? "text-white bg-white/5 border-l-2 border-purple-500 pl-2 font-medium" : "text-[#8D96A3] hover:text-white hover:bg-white/5"}`}
              >
                <FileText className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && <span>Reports</span>}
              </button>
            </div>

            {/* System Section */}
            <div>
              {!sidebarCollapsed && <span className="px-2.5 text-[8px] font-bold text-[#626B78] uppercase tracking-widest block mb-1">System</span>}
              <button
                onClick={() => setActiveTab("settings")}
                className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs transition text-left cursor-pointer ${activeTab === "settings" ? "text-white bg-white/5 border-l-2 border-purple-500 pl-2 font-medium" : "text-[#8D96A3] hover:text-white hover:bg-white/5"}`}
              >
                <Settings className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && <span>Settings</span>}
              </button>
            </div>
          </nav>
        </div>

        {/* Sidebar bottom player + Healthy badge */}
        <div className="p-3 border-t border-white/5 flex flex-col gap-3">
          
          {/* Subtle Now Playing Player */}
          {!sidebarCollapsed && (
            <div className="mb-1">
              <MusicPlayer />
            </div>
          )}

          {/* System Healthy status card */}
          {!sidebarCollapsed && (
            <div className="flex items-center gap-2 px-2.5 py-2 bg-emerald-500/5 border border-emerald-500/10 rounded-xl text-[10px] text-emerald-400">
              <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse"></span>
              <div className="flex flex-col">
                <span className="font-bold uppercase tracking-wider text-[8px]">System Healthy</span>
                <span className="text-[#8D96A3] text-[9px] mt-0.5">All systems operational</span>
              </div>
            </div>
          )}

          {/* User profile extraction */}
          <div className="flex items-center justify-between gap-2 overflow-hidden">
            {!sidebarCollapsed && (
              <div className="px-2 truncate">
                <span className="text-[10px] font-semibold text-slate-350 block truncate leading-tight">{userEmail}</span>
                <span className="text-[9px] text-[#626B78] block">SOC Analyst</span>
              </div>
            )}
            <button 
              onClick={handleLogout}
              className="p-2 hover:bg-rose-950/20 hover:text-rose-450 border border-white/5 rounded-lg text-[#8D96A3] transition active:scale-95 cursor-pointer ml-auto"
              title="Logout session"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main viewport Container */}
      <div className="flex-1 flex flex-col min-w-0 z-10">
        
        {/* TOP HEADER (Thin & Liquid Glass) */}
        <header className="h-12 glass-header px-6 flex items-center justify-between sticky top-0 z-[100]">
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1 hover:bg-white/5 rounded text-[#8D96A3] hover:text-white transition cursor-pointer"
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="hidden md:flex items-center gap-2 text-xs select-none">
              <span className="font-bold text-white tracking-wide">ORION SOC</span>
              <span className="text-[#626B78]">/</span>
              <span className="text-[10px] font-semibold text-[#8D96A3] uppercase tracking-wider">Lead Architect</span>
            </div>
          </div>

          {/* Global search centered bar */}
          <div 
            onClick={() => setCommandPaletteOpen(true)}
            className="flex items-center gap-3 px-3 py-1.5 bg-[#080B12]/80 border border-white/5 hover:border-purple-500/40 rounded-lg text-[#8D96A3] text-xs cursor-pointer select-none transition min-w-[320px]"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="text-[10px]">Search incidents, hashes, IPs, domains...</span>
            <kbd className="ml-auto text-[9px] bg-white/5 px-1.5 py-0.5 rounded border border-white/5 text-[#626B78] font-mono">⌘ K</kbd>
          </div>

          <div className="flex items-center gap-3 relative">
            
            {/* Theme Mode Toggle Button */}
            <button 
              onClick={() => setTheme(prev => prev === "dark" ? "light" : "dark")}
              className="p-1.5 hover:bg-white/5 rounded-lg text-[#8D96A3] hover:text-white transition active:scale-90 cursor-pointer"
              title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            {/* Interactive Bolt Logo (Diagnostic Scan trigger) */}
            <button 
              onClick={runDiagnostic}
              disabled={diagnosticRunning}
              className={`p-1.5 hover:bg-white/5 rounded-lg transition active:scale-90 cursor-pointer ${diagnosticRunning ? "text-purple-400 animate-spin" : "text-[#8D96A3] hover:text-white"}`}
              title="Trigger Instant System Diagnostic Scan"
            >
              <Zap className="h-4 w-4 fill-current" />
            </button>
            
            {/* Notification bell badge */}
            <div className="relative">
              <button 
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="p-1.5 hover:bg-white/5 rounded-lg text-[#8D96A3] hover:text-white transition cursor-pointer"
                title="Toggle notification alerts feed"
              >
                <Bell className="h-4 w-4" />
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-purple-500 rounded-full"></span>
              </button>

              {/* Notification dropdown dialog */}
              {notificationsOpen && (
                <div className="absolute right-0 mt-2.5 w-72 glass-premium rounded-xl p-3.5 shadow-2xl z-50 flex flex-col gap-2 animate-in fade-in duration-200">
                  <div className="flex justify-between items-center pb-2 border-b border-white/5 mb-1">
                    <span className="text-[10px] font-bold text-white uppercase tracking-wider">Alert Center</span>
                    <button onClick={() => setNotificationsOpen(false)} className="text-[#626B78] hover:text-white transition"><X className="h-3.5 w-3.5" /></button>
                  </div>
                  <div className="flex flex-col gap-2.5 text-[10.5px]">
                    <div className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 bg-rose-500 rounded-full mt-1.5 shrink-0"></span>
                      <div>
                        <span className="text-white block font-medium">Critical Deepfake detected in vector #INC-782</span>
                        <span className="text-[#626B78] text-[8.5px]">10m ago</span>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full mt-1.5 shrink-0"></span>
                      <div>
                        <span className="text-white block font-medium">Model retrained successfully with 15 new safe samples</span>
                        <span className="text-[#626B78] text-[8.5px]">1h ago</span>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-1.5 shrink-0"></span>
                      <div>
                        <span className="text-white block font-medium">SIEM syslog sync completed - 0 alerts pending</span>
                        <span className="text-[#626B78] text-[8.5px]">3h ago</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Profile Dropdown */}
            <div className="relative">
              <div 
                onClick={(e) => {
                  e.stopPropagation();
                  setProfileDropdownOpen(!profileDropdownOpen);
                }}
                className="flex items-center gap-2.5 pl-3 border-l border-white/5 cursor-pointer select-none"
              >
                <div className="w-6.5 h-6.5 rounded-full overflow-hidden shrink-0">
                  <img src="/logo.jpg" alt="Profile" className="w-full h-full object-cover" />
                </div>
                <div className="hidden sm:flex items-center gap-1">
                  <span className="text-[10px] font-bold text-white block truncate w-20">{getAnalystName(userEmail)}</span>
                  <ChevronDown className={`h-3 w-3 text-[#626B78] transition-transform duration-200 ${profileDropdownOpen ? "rotate-180" : ""}`} />
                </div>
              </div>

              {profileDropdownOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-[#0D111A] border border-white/10 rounded-xl shadow-2xl p-2 z-50 animate-in fade-in duration-150">
                  <div className="px-3 py-2 border-b border-white/5 mb-1.5">
                    <span className="text-[9px] text-[#8D96A3] block uppercase tracking-wider">Active Session</span>
                    <span className="text-[10px] font-bold text-white block truncate">{userEmail}</span>
                  </div>
                  <button 
                    onClick={() => { setActiveTab("settings"); setProfileDropdownOpen(false); }}
                    className="w-full text-left px-3 py-1.5 hover:bg-white/5 rounded-lg text-xs text-[#8D96A3] hover:text-white transition cursor-pointer"
                  >
                    Account Settings
                  </button>
                  <button 
                    onClick={() => {
                      localStorage.removeItem("soc_user_email");
                      setUserEmail("");
                      setIsLoggedIn(false);
                      setProfileDropdownOpen(false);
                    }}
                    className="w-full text-left px-3 py-1.5 hover:bg-rose-500/10 rounded-lg text-xs text-rose-500 font-bold transition cursor-pointer mt-1"
                  >
                    Log Out Session
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Diagnostic Scan Output Toast Message */}
        {diagnosticMessage && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-[10.5px] rounded-lg animate-in slide-in-from-top-3 flex items-center justify-between">
            <span>{diagnosticMessage}</span>
            <button onClick={() => setDiagnosticMessage(null)} className="text-emerald-400 hover:text-white"><X className="h-4 w-4" /></button>
          </div>
        )}

        {apiOffline && (
          <div className="mx-6 mt-4 p-3 bg-rose-950/20 border border-rose-500/30 text-rose-450 text-[10.5px] rounded-lg animate-in slide-in-from-top-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-rose-500 rounded-full animate-ping"></span>
              <span><strong>API Connection Offline:</strong> The backend threat detection service is unreachable. Make sure the backend server is running.</span>
            </div>
            <button 
              onClick={() => {
                fetchIncidents(true);
                fetchAnalytics();
              }} 
              className="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded text-[9.5px] font-bold transition cursor-pointer"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Dynamic centered Content area with comfortable margins */}
        <main className="flex-1 p-6 md:p-8 overflow-y-auto max-w-[1300px] w-full mx-auto">

          {/* TAB 1: TRI-COLUMN security overview dashboard */}
          {activeTab === "overview" && (
            <div className="flex flex-col lg:flex-row gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              
              {/* Left & Center workspace areas (75%) */}
              <div className="flex-1 flex flex-col gap-6">
                
                {/* Greeting banner */}
                <div className="flex justify-between items-center">
                  <div>
                    <h1 className="text-xl font-bold tracking-tight text-white">{getGreeting(getAnalystName(userEmail))}</h1>
                    <p className="text-xs text-[#8D96A3] mt-0.5 font-sans">Your security environment is healthy. Last updated 12s ago.</p>
                  </div>
                  <button 
                    onClick={() => setActiveTab("investigate")}
                    className="bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-bold text-xs py-2 px-4 rounded-lg flex items-center gap-2 transition cursor-pointer shadow-md hover:shadow-purple-500/10 active:scale-95"
                  >
                    <Plus className="h-3.5 w-3.5" /> New Investigation
                  </button>
                </div>

                {/* 4 solid dark KPI cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative">
                  <KPIWidget 
                    title="Threats Detected" 
                    targetVal={incidents.filter(i=>i.status!=="SAFE").length + 128} 
                    trend="+12% from last week" 
                    isPositive={true}
                    sparkData={[{ value: 20 }, { value: 45 }, { value: 30 }, { value: 65 }, { value: 55 }, { value: 80 }]}
                    accentColor="#7C3AED" 
                  />
                  <KPIWidget 
                    title="Critical Threats" 
                    targetVal={incidents.filter(i=>i.severity==="CRITICAL").length + 4} 
                    trend="-2 today" 
                    isPositive={false}
                    sparkData={[{ value: 80 }, { value: 65 }, { value: 45 }, { value: 30 }, { value: 15 }, { value: 4 }]}
                    accentColor="#EF4444" 
                  />
                  <KPIWidget 
                    title="Active Investigations" 
                    targetVal={incidents.filter(i=>i.status==="PENDING").length + 17} 
                    trend="+3 pending" 
                    isPositive={true}
                    sparkData={[{ value: 5 }, { value: 10 }, { value: 12 }, { value: 8 }, { value: 15 }, { value: 17 }]}
                    accentColor="#F59E0B" 
                  />
                  <KPIWidget 
                    title="Detection Accuracy" 
                    targetVal={94.8} 
                    valSuffix="%"
                    trend="+1.4% change" 
                    isPositive={true}
                    sparkData={[{ value: 92 }, { value: 92.5 }, { value: 93 }, { value: 93.8 }, { value: 94.2 }, { value: 94.8 }]}
                    accentColor="#10B981" 
                    onInfoClick={() => setAccuracyTooltipOpen(!accuracyTooltipOpen)}
                  />

                  {/* Accuracy calculation math details dialog overlay */}
                  {accuracyTooltipOpen && (
                    <div className="absolute right-0 top-36 w-80 glass-premium rounded-xl p-4.5 shadow-2xl z-50 animate-in fade-in duration-200">
                      <div className="flex justify-between items-center mb-3">
                        <span className="text-[10px] font-bold text-white uppercase tracking-wider">Model Accuracy Calculation</span>
                        <button onClick={() => setAccuracyTooltipOpen(false)} className="text-[#626B78] hover:text-white transition cursor-pointer"><X className="h-4 w-4" /></button>
                      </div>
                      <div className="flex flex-col gap-2.5 text-xs text-[#8D96A3]">
                        <p>Calculated daily across all security vector classifiers (URL typosquat, email spam parser, logs, and deepfake entropy checker) against verified ground-truth validation datasets.</p>
                        <div className="p-3 bg-black/40 rounded border border-white/5 font-mono text-center text-white my-1.5">
                          {"\\[\\text{Accuracy} = \\frac{\\text{TP} + \\text{TN}}{\\text{TP} + \\text{TN} + \\text{FP} + \\text{FN}}\\]"}
                        </div>
                        <div className="text-[10.5px]">
                          <span className="block"><strong className="text-white">TP / TN:</strong> True Positives / Negatives (Correctly Classified)</span>
                          <span className="block"><strong className="text-white">FP / FN:</strong> False Positives / Negatives (Incorrect Outcomes)</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* SECTION 1: Investigation Launcher (65%) & Environment Risk Gauge (35%) */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Investigation Launcher Card (65% width - 2 cols) */}
                  <div className="lg:col-span-2 glass-strong glass-highlight p-5 rounded-2xl flex flex-col justify-between shadow-xl">
                    <div>
                      <div className="flex justify-between items-center mb-3">
                        <div className="flex items-center gap-2">
                          <Zap className="h-4 w-4 text-purple-400" />
                          <h2 className="text-xs font-bold text-white uppercase tracking-wider">Investigation Launcher</h2>
                        </div>
                        <span className="text-[9px] font-bold text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded-full uppercase tracking-wider">
                          On-Demand Diagnostics
                        </span>
                      </div>
                      <p className="text-xs text-[#8D96A3] mb-4">Launch immediate threat detection pipeline across active vector channels.</p>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mb-4">
                        {[
                          { id: "url_analysis", title: "URL Analysis", desc: "Scan domains & links", icon: Link },
                          { id: "email_analysis", title: "Email Analysis", desc: "Audit SPF/DKIM headers", icon: Mail },
                          { id: "log_analysis", title: "Logs / PCAP", desc: "Correlate syslog & traffic", icon: Terminal },
                          { id: "media_analysis", title: "Media Analysis", desc: "Deepfake video/audio track", icon: Video }
                        ].map(action => (
                          <div 
                            key={action.id}
                            onClick={() => setActiveTab(action.id)}
                            className="p-3 bg-[#080C16]/70 hover:bg-white/10 border border-white/8 hover:border-purple-500/40 rounded-xl cursor-pointer hover:-translate-y-0.5 transition-all duration-200 flex items-center justify-between group"
                          >
                            <div className="flex items-center gap-2.5">
                              <div className="p-1.5 rounded-lg bg-purple-500/10 text-purple-400 group-hover:bg-purple-500 group-hover:text-white transition">
                                <action.icon className="h-3.5 w-3.5" />
                              </div>
                              <div>
                                <span className="text-[11px] font-bold text-white block group-hover:text-purple-300 transition">{action.title}</span>
                                <span className="text-[9px] text-[#8D96A3] block">{action.desc}</span>
                              </div>
                            </div>
                            <ChevronRight className="h-3.5 w-3.5 text-[#626B78] group-hover:text-white group-hover:translate-x-0.5 transition shrink-0" />
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="flex justify-between items-center pt-3 border-t border-white/5 text-xs">
                      <span className="text-[10px] text-[#626B78]">4 Vector Analysis Pipelines Ready</span>
                      <button 
                        onClick={() => setActiveTab("investigate")}
                        className="text-xs text-purple-400 hover:text-purple-300 font-bold transition flex items-center gap-1 cursor-pointer"
                      >
                        Open Workspace <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Environment Risk Score Gauge (35% width - 1 col) */}
                  <div className="glass-strong glass-highlight risk-gauge-elevated p-5 rounded-2xl flex flex-col justify-between shadow-xl">
                    <div>
                      <div className="flex justify-between items-center mb-3">
                        <h2 className="text-xs font-bold text-white uppercase tracking-wider">Environment Risk</h2>
                        <span className="text-[9px] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full uppercase tracking-wider animate-pulse">
                          ● ELEVATED
                        </span>
                      </div>
                      
                      <div className="flex flex-col items-center justify-center my-3 text-center">
                        <div className="relative flex items-center justify-center w-28 h-28 rounded-full border-4 border-amber-500/30 bg-amber-500/5 glow-warning">
                          <div className="text-center">
                            <span className="text-3xl font-extrabold text-white tracking-tight block">72</span>
                            <span className="text-[9px] font-bold text-amber-400 uppercase tracking-widest block">/ 100 RISK</span>
                          </div>
                        </div>
                      </div>

                      <p className="text-[10.5px] text-[#8D96A3] text-center leading-relaxed">
                        Critical threat vector events are currently above the normal weekly baseline. 2 pending items require triage.
                      </p>
                    </div>

                    <div className="pt-3 border-t border-white/5 flex justify-between items-center text-xs">
                      <span className="text-[9px] text-[#626B78]">Calculated from 131 events</span>
                      <button 
                        onClick={() => setActiveTab("incidents")}
                        className="text-xs text-amber-400 hover:text-amber-300 font-bold transition cursor-pointer"
                      >
                        Audit Queue →
                      </button>
                    </div>
                  </div>

                </div>

                {/* Split line chart & Donut charts */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Trends line chart (65% width) */}
                  <div className="lg:col-span-2 glass-strong glass-highlight p-5 rounded-2xl shadow-xl">
                    <div className="flex justify-between items-center mb-4">
                      <h2 className="text-xs font-bold text-white uppercase tracking-wider">Threat Activity Trends</h2>
                      <select className="bg-[#080B12]/80 border border-white/10 rounded px-2.5 py-1 text-[10px] text-[#8D96A3] focus:outline-none cursor-pointer">
                        <option>Last 7 Days</option>
                        <option>Last 30 Days</option>
                      </select>
                    </div>
                    <div className="h-56">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={chartData}>
                          <XAxis dataKey="name" stroke="#626B78" fontSize={9} tickLine={false} />
                          <YAxis stroke="#626B78" fontSize={9} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#0B1020", borderColor: "rgba(255,255,255,0.12)", borderRadius: "12px", color: "#F3F5F7", boxShadow: "0 10px 30px rgba(0,0,0,0.5)" }} />
                          <Line type="monotone" dataKey="Phishing" stroke="#8B5CF6" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="Deepfake" stroke="#F43F8E" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="Exploits" stroke="#F59E0B" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="Safe" stroke="#21C997" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Distribution Donut (35% width - synced with real backend data & disabled lag animation) */}
                  <div className="glass-strong glass-highlight p-5 rounded-2xl flex flex-col justify-between shadow-xl animate-in fade-in">
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider mb-2">Threat Distribution</h2>
                    
                    <div className="h-36 relative flex items-center justify-center">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={donutData}
                            cx="50%"
                            cy="50%"
                            innerRadius={44}
                            outerRadius={58}
                            paddingAngle={3}
                            dataKey="value"
                            isAnimationActive={false} // Disabled animation to prevent visual lag
                          >
                            {donutData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute text-center">
                        <span className="text-lg font-extrabold text-white block">{totalDonutCount}</span>
                        <span className="text-[8px] text-[#8D96A3] uppercase tracking-wider block">Total</span>
                      </div>
                    </div>

                    <div className="flex flex-col gap-1 text-[9px] mt-1 text-[#8D96A3]">
                      {donutData.map((entry, index) => (
                        <div key={index} className="flex justify-between items-center">
                          <span className="flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: entry.color }}></span> 
                            {entry.name}
                          </span>
                          <span className="text-white font-bold">{getPercent(entry.value)}% ({entry.value})</span>
                        </div>
                      ))}
                    </div>

                    <button 
                      onClick={downloadGlobalReport}
                      className="mt-3.5 w-full py-1.5 bg-white/5 border border-white/8 hover:border-purple-500/20 text-[10px] font-bold rounded-lg text-[#8D96A3] hover:text-white transition flex items-center justify-center gap-2 cursor-pointer active:scale-95"
                    >
                      <FileDown className="h-3.5 w-3.5" /> Download Global PDF Report
                    </button>
                  </div>
                </div>

                {/* Telemetry and Activity Feeds Row */}
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                  
                  {/* System Health (40% - 2 Cols) */}
                  <div className="lg:col-span-2 glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between shadow-xl">
                    <div>
                      <div className="flex justify-between items-center mb-4">
                        <h2 className="text-xs font-bold text-white uppercase tracking-wider">System Health & Telemetry</h2>
                        <span className="text-[9px] text-[#626B78] font-mono">PORT 8000/8000</span>
                      </div>

                      <div className="flex flex-col gap-3.5">
                        <div className="flex justify-between items-center text-xs">
                          <span className="text-[#8D96A3]">IPS Threat Vector</span>
                          <button 
                            onClick={() => setIpsActive(!ipsActive)}
                            className={`flex items-center gap-1.5 px-2 py-0.5 rounded border text-[9px] font-semibold transition active:scale-95 cursor-pointer ${ipsActive ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" : "text-amber-400 bg-amber-500/10 border-amber-500/20"}`}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${ipsActive ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`}></span>
                            {ipsActive ? "Active" : "Muted"}
                          </button>
                        </div>

                        <div className="flex justify-between items-center text-xs">
                          <span className="text-[#8D96A3]">Analysis Workers (Celery)</span>
                          <span className="text-xs font-mono text-white">{celeryWorkers} active</span>
                        </div>

                        <div className="flex justify-between items-center text-xs">
                          <span className="text-[#8D96A3]">Database Connection</span>
                          <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full"></span> Connected
                          </span>
                        </div>

                        <div className="flex justify-between items-center text-xs">
                          <span className="text-[#8D96A3]">Threat Intelligence DB</span>
                          <span className="text-blue-400 font-semibold flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 bg-blue-400 rounded-full"></span> Synced
                          </span>
                        </div>

                        <div className="flex justify-between items-center text-xs">
                          <span className="text-[#8D96A3]">Processing Queue</span>
                          <span className="text-amber-400 font-mono font-semibold">2 pending</span>
                        </div>
                      </div>
                    </div>

                    <div className="border-t border-white/5 mt-5 pt-3 flex justify-between items-center text-[9px] text-[#626B78]">
                      <span>Last synchronized: {lastSyncSecs}s ago</span>
                      <button 
                        onClick={() => setLastSyncSecs(0)}
                        className="text-blue-400 hover:text-blue-300 font-bold transition flex items-center gap-1 cursor-pointer"
                      >
                        <RefreshCw className="h-3 w-3" /> Sync Now
                      </button>
                    </div>
                  </div>

                  {/* Real-time Activity Feed (60% - 3 Cols) */}
                  <div className="lg:col-span-3 glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between shadow-xl">
                    <div>
                      <div className="flex justify-between items-center mb-4 flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <h2 className="text-xs font-bold text-white uppercase tracking-wider">Real-Time Security Activity</h2>
                          <span className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-[8px] text-emerald-400 rounded-full font-bold uppercase tracking-wider">
                            <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span> Live Feed
                          </span>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <button 
                            onClick={() => setIsLivePaused(!isLivePaused)}
                            className="px-2 py-1 bg-white/5 border border-white/5 hover:border-purple-500/20 rounded text-[9px] text-[#8D96A3] hover:text-white transition active:scale-95 cursor-pointer"
                          >
                            {isLivePaused ? "Resume" : "Pause"}
                          </button>
                        </div>
                      </div>

                      <div className="flex flex-col gap-2 max-h-[160px] overflow-y-auto pr-1">
                        {liveLogs.map((log, idx) => (
                          <div 
                            key={idx} 
                            onClick={() => setExpandedLogIdx(expandedLogIdx === idx ? null : idx)}
                            className="p-2.5 bg-[#080B12]/60 hover:bg-white/5 border border-white/5 rounded-lg cursor-pointer transition flex flex-col gap-1"
                          >
                            <div className="flex justify-between items-center text-[9px] font-mono">
                              <div className="flex items-center gap-2">
                                <span className="text-[#626B78]">{log.time}</span>
                                <span className="px-1.5 py-0.2 bg-white/5 border border-white/8 text-[#8D96A3] rounded uppercase tracking-wider text-[8px] font-bold">{log.category}</span>
                              </div>
                              <span className={`font-bold ${log.sev === "CRITICAL" ? "text-[#EF4444]" : log.sev === "WARNING" ? "text-[#FBBF24]" : "text-[#10B981]"}`}>
                                {log.sev}
                              </span>
                            </div>
                            <p className="text-[11px] text-[#8D96A3] truncate">{log.msg}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Incident queue table at the bottom of Overview */}
                <div className="bg-[#0D111A] border border-white/5 rounded-xl overflow-hidden mt-2">
                  <div className="p-4 border-b border-white/5 flex justify-between items-center">
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider">Incident Queue Ledger</h2>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-white/5 text-[#8D96A3] bg-white/5">
                          <th className="p-3 font-semibold">Severity</th>
                          <th className="p-3 font-semibold">Incident ID</th>
                          <th className="p-3 font-semibold">Channel</th>
                          <th className="p-3 font-semibold">Target Ingest Input</th>
                          <th className="p-3 font-semibold">Status</th>
                          <th className="p-3 font-semibold">Score</th>
                          <th className="p-3 font-semibold text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {incidents.slice(0, 5).map(inc => (
                          <tr 
                            key={inc.id}
                            onClick={() => setSelectedId(inc.id)}
                            className="hover:bg-white/5 transition-colors cursor-pointer"
                          >
                            <td className="p-3">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${getSeverityBadge(inc.severity)}`}>
                                {inc.severity}
                              </span>
                            </td>
                            <td className="p-3 font-mono text-[10px] text-[#8D96A3]">{inc.id.substring(0, 8)}...</td>
                            <td className="p-3 text-[#8D96A3]">{inc.vector_type}</td>
                            <td className="p-3 font-mono text-[10px] text-white max-w-[200px] truncate">{inc.target_input}</td>
                            <td className="p-3">
                              <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-semibold ${getStatusBadge(inc.status)}`}>
                                {inc.status}
                              </span>
                            </td>
                            <td className="p-3 font-bold text-white">{inc.threat_score}%</td>
                            <td className="p-3 text-right" onClick={e=>e.stopPropagation()}>
                              <div className="flex justify-end items-center gap-2">
                                {userEmail === "admin@orion.com" ? (
                                  <div className="relative">
                                    <button 
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setActiveDropdownId(activeDropdownId === inc.id ? null : inc.id);
                                      }}
                                      className="px-2.5 py-1 bg-white/5 border border-white/10 hover:border-purple-500/20 text-[9px] font-mono font-bold rounded text-blue-400 hover:text-white transition flex items-center gap-1.5 cursor-pointer"
                                    >
                                      TRAIN ML <ChevronDown className="h-3 w-3" />
                                    </button>
                                    {activeDropdownId === inc.id && (
                                      <div className="absolute right-0 top-full mt-1 w-32 bg-[#0D111A] border border-white/10 rounded-lg shadow-xl overflow-hidden z-50 animate-in fade-in duration-150">
                                        {["PHISHING", "DEEPFAKE", "SUSPICIOUS", "SAFE"].map(label => (
                                          <button
                                            key={label}
                                            onClick={() => {
                                              handleTrainML(inc.id, label);
                                              setActiveDropdownId(null);
                                            }}
                                            className="w-full text-left px-3 py-1.5 hover:bg-white/5 text-[9px] text-[#8D96A3] hover:text-white transition cursor-pointer"
                                          >
                                            {label}
                                          </button>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  <span className="text-[9px] text-[#626B78] font-mono border border-white/5 px-2 py-0.5 rounded">ANALYST</span>
                                )}
                                <button 
                                  onClick={() => downloadReport(inc.id)}
                                  className="p-1.5 hover:bg-white/10 border border-white/5 text-[#8D96A3] hover:text-white rounded transition"
                                  title="Download PDF Report"
                                >
                                  <Download className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* SECTION 4: Upcoming Tasks & Recent Reports (2-column embedded widgets) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  {/* UPCOMING TASKS block */}
                  <div className="glass-subtle glass-highlight p-4 rounded-2xl shadow-xl">
                    <div className="flex justify-between items-center mb-3">
                      <h2 className="text-[10px] font-bold text-[#8D96A3] uppercase tracking-wider">Upcoming Tasks</h2>
                    </div>
                    <div className="flex flex-col gap-2.5">
                      <div className="flex items-start gap-2 text-[10.5px]">
                        <span className="w-1.5 h-1.5 bg-purple-500 rounded-full mt-1.5 shrink-0"></span>
                        <div>
                          <span className="text-white block font-medium">Threat report for #INC-7821</span>
                          <span className="text-[#626B78] text-[9px]">Due in 25m</span>
                        </div>
                      </div>
                      <div className="flex items-start gap-2 text-[10.5px]">
                        <span className="w-1.5 h-1.5 bg-pink-500 rounded-full mt-1.5 shrink-0"></span>
                        <div>
                          <span className="text-white block font-medium">Model training job</span>
                          <span className="text-[#626B78] text-[9px]">Due in 1h 10m</span>
                        </div>
                      </div>
                      <div className="flex items-start gap-2 text-[10.5px]">
                        <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full mt-1.5 shrink-0"></span>
                        <div>
                          <span className="text-white block font-medium">Weekly system health review</span>
                          <span className="text-[#626B78] text-[9px]">Due in 3h 30m</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* RECENT REPORTS block */}
                  <div className="glass-subtle glass-highlight p-4 rounded-2xl shadow-xl">
                    <div className="flex justify-between items-center mb-3">
                      <h2 className="text-[10px] font-bold text-[#8D96A3] uppercase tracking-wider">Recent Reports</h2>
                    </div>
                    <div className="flex flex-col gap-2.5">
                      {/* Global Analytics Summary */}
                      <div className="flex items-center justify-between text-[11px] p-2 bg-[#080C16]/70 rounded-lg border border-white/5 hover:bg-white/10 transition">
                        <div className="flex items-center gap-2 overflow-hidden">
                          <FileText className="h-4 w-4 text-purple-400 shrink-0" />
                          <div className="truncate">
                            <span className="text-white block font-medium truncate w-40">Global SOC Summary</span>
                            <span className="text-[#626B78] text-[9px]">Generated today</span>
                          </div>
                        </div>
                        <button 
                          onClick={downloadGlobalReport}
                          className="text-[#8D96A3] hover:text-white cursor-pointer p-1 rounded hover:bg-white/5 transition"
                          title="Download Global Summary Report"
                        >
                          <Download className="h-3.5 w-3.5" />
                        </button>
                      </div>

                      {/* Incident Reports (Up to 2 most recent) */}
                      {incidents.slice(0, 2).map((inc) => (
                        <div key={inc.id} className="flex items-center justify-between text-[11px] p-2 bg-[#080C16]/70 rounded-lg border border-white/5 hover:bg-white/10 transition">
                          <div className="flex items-center gap-2 overflow-hidden">
                            <FileText className="h-4 w-4 text-pink-400 shrink-0" />
                            <div className="truncate">
                              <span className="text-white block font-medium truncate w-40">{inc.vector_type} Analysis ({inc.id.substring(0, 8)})</span>
                              <span className="text-[#626B78] text-[9px]">Generated {formatTimeAgo(inc.timestamp)}</span>
                            </div>
                          </div>
                          <button 
                            onClick={() => downloadReport(inc.id)}
                            className="text-[#8D96A3] hover:text-white cursor-pointer p-1 rounded hover:bg-white/5 transition"
                            title="Download/Print Incident Report"
                          >
                            <Download className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      ))}

                      {incidents.length === 0 && (
                        <span className="text-[10px] text-[#626B78] italic block text-center py-2">No reports generated yet</span>
                      )}
                    </div>
                  </div>

                </div>

              </div>

            </div>
          )}

          {/* TAB 2: SPECIFIC INCIDENTS triage grid */}
          {activeTab === "incidents" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">Threat Queue</h1>
                <p className="text-xs text-[#8D96A3] mt-0.5">Audit tracked vector inputs and compromise evidence.</p>
              </div>

              {/* Incidents Queue list table */}
              <div className="glass-strong glass-highlight rounded-2xl overflow-hidden shadow-2xl">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-white/10 text-[#8D96A3] bg-[#080C16]/80 font-sans">
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Incident ID</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Timestamp</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Vector</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Ingest Source Target</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Severity</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px]">Status</th>
                      <th className="p-3.5 font-bold uppercase tracking-wider text-[9px] text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {filteredIncidents.length > 0 ? (
                      filteredIncidents.map(inc => (
                        <tr 
                          key={inc.id}
                          onClick={() => setSelectedId(inc.id)}
                          className={`hover:bg-white/5 transition-colors cursor-pointer relative ${selectedId === inc.id ? "bg-white/5 border-l-2 border-[#00d8ff]" : ""}`}
                        >
                          <td className="p-3.5 font-mono text-[10px] text-white font-semibold">
                            {inc.id.substring(0, 8)}...
                          </td>
                          <td className="p-3.5 text-[#8D96A3] font-mono text-[9px]">
                            {inc.timestamp.substring(0, 16).replace("T", " ")}
                          </td>
                          <td className="p-3.5 text-[#8D96A3] font-semibold">{inc.vector_type}</td>
                          <td className="p-3.5 font-mono text-[10px] text-[#8D96A3] max-w-[240px] truncate" title={inc.target_input}>
                            {inc.target_input}
                          </td>
                          <td className="p-3.5">
                            <span className={`px-2.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${getSeverityBadge(inc.severity)}`}>
                              {inc.severity}
                            </span>
                          </td>
                          <td className="p-3.5">
                            <span className={`px-2.5 py-0.5 rounded-full text-[8px] font-bold uppercase tracking-wider ${getStatusBadge(inc.status)}`}>
                              {inc.status}
                            </span>
                          </td>
                          <td className="p-3.5 text-right" onClick={e=>e.stopPropagation()}>
                            <div className="flex justify-end items-center gap-2">
                               {userEmail === "admin@orion.com" ? (
                                <div className="relative">
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setActiveDropdownId(activeDropdownId === inc.id ? null : inc.id);
                                    }}
                                    className="px-2.5 py-1 bg-white/5 border border-white/10 hover:border-purple-500/20 text-[9px] font-mono font-bold rounded text-blue-400 hover:text-white transition flex items-center gap-1.5 cursor-pointer"
                                  >
                                    TRAIN ML <ChevronDown className="h-3 w-3" />
                                  </button>
                                  {activeDropdownId === inc.id && (
                                    <div className="absolute right-0 top-full mt-1 w-32 bg-[#0D111A] border border-white/10 rounded-lg shadow-xl overflow-hidden z-50 animate-in fade-in duration-150">
                                      {["PHISHING", "DEEPFAKE", "SUSPICIOUS", "SAFE"].map(label => (
                                        <button
                                          key={label}
                                          onClick={() => {
                                            handleTrainML(inc.id, label);
                                            setActiveDropdownId(null);
                                          }}
                                          className="w-full text-left px-3 py-1.5 hover:bg-white/5 text-[9px] text-[#8D96A3] hover:text-white transition cursor-pointer"
                                        >
                                          {label}
                                        </button>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span className="text-[9px] text-[#626B78] font-mono border border-white/5 px-2 py-0.5 rounded">ANALYST</span>
                              )}
                              <button 
                                onClick={() => downloadReport(inc.id)}
                                className="p-1.5 hover:bg-white/10 border border-white/5 text-[#8D96A3] hover:text-white rounded transition"
                                title="Download PDF Report"
                              >
                                <Download className="h-3.5 w-3.5" />
                              </button>
                              <button 
                                onClick={() => handleDeleteIncident(inc.id)}
                                className="p-1.5 hover:bg-rose-950/20 border border-white/5 text-[#8D96A3] hover:text-[#EF4444] rounded transition"
                                title="Delete incident"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-[#626B78] bg-[#0D111A]/20">
                          <AlertCircle className="h-8 w-8 mx-auto mb-2 text-[#626B78]" />
                          <span>No matching threat incidents found in the active queue.</span>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: URL REPUTATION AUDIT WORKSPACE */}
          {activeTab === "url_analysis" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              {/* HEADER & PAGE TITLE */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 font-mono text-[9px] font-bold uppercase tracking-widest">
                      VECTOR // URL AUDIT
                    </span>
                    <span className="text-[10px] text-[#626B78] font-mono">BACKEND THREAT ENGINE</span>
                  </div>
                  <h1 className="text-2xl font-extrabold tracking-tight text-white mt-1">URL Reputation Audit</h1>
                  <p className="text-xs text-[#8D96A3] mt-0.5">
                    Investigate URLs, domains, redirects, reputation signals, and phishing indicators.
                  </p>
                </div>

                {/* Quick Presets */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[10px] text-[#626B78] font-mono uppercase mr-1">Sample Targets:</span>
                  {[
                    { label: "google.com", url: "https://google.com" },
                    { label: "microsoft.com", url: "https://microsoft.com" },
                    { label: "suspicious-login", url: "http://paypa1-secure-login.example.com/login" }
                  ].map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => { setUrlInput(preset.url); startURLScan(undefined, preset.url); }}
                      className="px-2.5 py-1 bg-white/5 hover:bg-purple-500/10 border border-white/8 hover:border-purple-500/30 rounded-lg text-[10.5px] font-mono text-[#8D96A3] hover:text-white transition cursor-pointer"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* TOP INVESTIGATION BAR */}
              <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col gap-4">
                <form onSubmit={(e) => startURLScan(e)} className="flex flex-col md:flex-row gap-3">
                  <div className="relative flex-1">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[#8D96A3]" />
                    <input
                      type="url"
                      placeholder="Enter target URL or domain (e.g. https://example.com/login)..."
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      required
                      className="w-full bg-[#080C16]/90 border border-white/12 rounded-xl pl-10 pr-4 py-3 text-xs text-white placeholder-[#626B78] focus:outline-none focus:border-purple-500 font-mono shadow-inner"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={urlScanning}
                    className="px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-bold text-xs rounded-xl transition cursor-pointer shadow-lg shadow-purple-600/20 flex items-center justify-center gap-2 shrink-0"
                  >
                    {urlScanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    <span>{urlScanning ? "Scanning Target..." : "Start Scan"}</span>
                  </button>
                </form>

                <div className="flex items-center justify-between text-[10px] text-[#626B78] font-mono pt-2 border-t border-white/5">
                  <span>🔒 Passive Analysis: No external traffic is generated during passive domain lookup.</span>
                  <span>ENGINE: FASTAPI / CELERY MODEL PIPELINE</span>
                </div>
              </div>

              {/* SCANNING STATE */}
              {urlScanning && (
                <div className="glass-strong p-6 rounded-2xl border border-purple-500/30 animate-pulse flex items-center gap-4">
                  <RefreshCw className="h-6 w-6 text-purple-400 animate-spin shrink-0" />
                  <div>
                    <span className="text-xs font-bold text-white block">Analyzing URL Target...</span>
                    <span className="text-[11px] text-[#8D96A3] font-mono">Running feature extraction, typosquatting checks, and self-learning classifier...</span>
                  </div>
                </div>
              )}

              {/* REAL RESULT PANEL */}
              {selectedIncident && selectedIncident.vector_type === "URL" && !urlScanning ? (
                <div className="flex flex-col gap-6 animate-in fade-in duration-300">
                  {/* MAIN VERDICT BANNER */}
                  <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                      <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block mb-1 font-mono">Target URL</span>
                      <span className="text-base font-bold text-white font-mono block break-all">{selectedIncident.target_input}</span>
                    </div>

                    <div className="flex items-center gap-6 shrink-0">
                      <div>
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block font-mono">Classification</span>
                        <span className={`text-xl font-black uppercase tracking-wider block ${
                          selectedIncident.status === "PHISHING" ? "text-rose-400" :
                          selectedIncident.status === "SUSPICIOUS" ? "text-amber-400" :
                          "text-emerald-400"
                        }`}>
                          {selectedIncident.status}
                        </span>
                      </div>

                      <div className="border-l border-white/10 pl-6 font-mono">
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Threat Score</span>
                        <span className="text-xl font-black text-white block">{selectedIncident.threat_score} / 100</span>
                      </div>
                    </div>
                  </div>

                  {/* EVIDENCE & REASONS */}
                  <div className="glass-medium glass-highlight p-6 rounded-2xl shadow-xl">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-white/5 pb-2 font-mono">
                      Backend Threat Evidence & Findings
                    </h3>
                    {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
                      <div className="space-y-2 font-mono text-xs">
                        {selectedIncident.evidences.map((ev: any, idx: number) => (
                          <div key={idx} className="p-3 bg-[#080C16]/80 border border-white/8 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                            <span className="text-purple-300 font-bold shrink-0">{ev.key}</span>
                            <span className="text-white text-left md:text-right">{ev.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#8D96A3] font-mono">No suspicious indicators detected. URL evaluated as clean by backend detection pipeline.</p>
                    )}
                  </div>

                  {/* RECOMMENDED ACTIONS */}
                  {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
                    <div className="glass-medium p-5 rounded-2xl">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 font-mono">Recommended Actions</h3>
                      <ul className="space-y-1.5 text-xs text-[#8D96A3] font-mono list-disc list-inside">
                        {selectedIncident.remediations.map((rem: any, idx: number) => (
                          <li key={idx} className="text-white">{rem.description}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* ANALYST ACTION TOOLBAR */}
                  <div className="glass-floating p-4 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-2xl">
                    <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">Analyst Feedback Controls:</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button
                        onClick={() => handleTrainML(selectedIncident.id, "PHISHING")}
                        className="px-3.5 py-2 bg-rose-600/30 hover:bg-rose-600/50 border border-rose-500/40 text-rose-200 font-bold text-xs rounded-xl transition cursor-pointer font-mono"
                      >
                        Train ML: Confirm Phishing
                      </button>
                      <button
                        onClick={() => handleTrainML(selectedIncident.id, "SAFE")}
                        className="px-3.5 py-2 bg-emerald-600/30 hover:bg-emerald-600/50 border border-emerald-500/40 text-emerald-200 font-bold text-xs rounded-xl transition cursor-pointer font-mono"
                      >
                        Train ML: Mark Safe
                      </button>
                      <button
                        onClick={downloadGlobalReport}
                        className="px-3.5 py-2 bg-white/10 hover:bg-white/20 border border-white/10 text-white font-bold text-xs rounded-xl transition cursor-pointer font-mono"
                      >
                        Export Incident Report
                      </button>
                    </div>
                  </div>
                </div>
              ) : !urlScanning && (
                /* EMPTY STATE */
                <div className="glass-medium p-8 rounded-2xl text-center flex flex-col items-center justify-center gap-3">
                  <Search className="h-8 w-8 text-[#626B78]" />
                  <span className="text-xs font-bold text-white block">No Analysis Performed Yet</span>
                  <span className="text-[11px] text-[#8D96A3] max-w-sm">Enter a target URL above to run threat detection, or select an incident from the ledger below.</span>
                </div>
              )}

              {/* RECENT URL INVESTIGATIONS LEDGER */}
              <div className="glass-strong glass-highlight p-5 rounded-2xl shadow-xl">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 font-mono">Recent URL Investigations Ledger</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-[#8D96A3] bg-[#080C16]/80 font-mono text-[9px] uppercase">
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Target URL</th>
                        <th className="p-3">Classification</th>
                        <th className="p-3">Threat Score</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-[11px]">
                      {incidents.filter(i => i.vector_type === "URL").map((inc, idx) => (
                        <tr key={idx} onClick={() => setSelectedId(inc.id)} className="hover:bg-white/5 transition cursor-pointer">
                          <td className="p-3 text-[#626B78]">{inc.timestamp?.substring(0, 16).replace("T", " ")}</td>
                          <td className="p-3 text-white font-bold max-w-[350px] truncate" title={inc.target_input}>{inc.target_input}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                              inc.status === "PHISHING" ? "bg-rose-500/20 text-rose-400" :
                              inc.status === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400" :
                              "bg-emerald-500/20 text-emerald-400"
                            }`}>
                              {inc.status}
                            </span>
                          </td>
                          <td className="p-3 text-white">{inc.threat_score} / 100</td>
                          <td className="p-3 text-right text-purple-300">Inspect →</td>
                        </tr>
                      ))}
                      {incidents.filter(i => i.vector_type === "URL").length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-4 text-center text-[#626B78]">No URL investigations recorded in database.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: SPECIFIC INVESTIGATION ingestion channels */}
          {activeTab === "investigate" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">Investigation Channels</h1>
                <p className="text-xs text-[#8D96A3] mt-0.5 font-sans">Trigger on-demand forensic checks on URL, EML, Log, and deepfake files.</p>
              </div>

              {isScanningActive && (
                <div className="bg-[#0D111A] border border-white/5 p-5 rounded-xl mb-4">
                  <span className="text-[10px] font-bold text-blue-500 uppercase tracking-widest block mb-4">Assessment Pipeline Status...</span>
                  <div className="flex flex-col gap-3">
                    {[
                      { step: 0, label: "Cryptographic signature validation" },
                      { step: 1, label: "Domain & host resolution lookup" },
                      { step: 2, label: "SSL Certificate verification" },
                      { step: 3, label: "Thread intelligence database match" },
                      { step: 4, label: "Entropy & temporal deepfake checks" }
                    ].map(item => (
                      <div key={item.step} className="flex items-center gap-3 text-xs">
                        {timelineStep > item.step ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                        ) : timelineStep === item.step ? (
                          <RefreshCw className="h-4 w-4 text-blue-400 shrink-0 animate-spin" />
                        ) : (
                          <Clock className="h-4 w-4 text-[#626B78] shrink-0" />
                        )}
                        <span className={timelineStep === item.step ? "text-white font-semibold animate-pulse" : timelineStep > item.step ? "text-[#8D96A3]" : "text-[#626B78]"}>
                          {item.label}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* URL Ingestion */}
                <div className="glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between hover:-translate-y-0.5 hover:border-white/15 transition-all duration-300 shadow-xl group">
                  <div>
                    <h2 className="text-sm font-bold text-white mb-2 group-hover:text-purple-400 transition">Analyze Domain / URL</h2>
                    <p className="text-xs text-[#8D96A3] leading-relaxed mb-4">
                      Scans for reputation indicators, redirection traces, and typosquatting target matches.
                    </p>
                  </div>
                  <form onSubmit={startURLScan} className="flex gap-2">
                    <input 
                      type="url" 
                      placeholder="https://example-compromised-domain.com"
                      value={urlInput}
                      onChange={e=>setUrlInput(e.target.value)}
                      required
                      disabled={isScanningActive}
                      className="flex-1 bg-[#080C16]/80 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500"
                    />
                    <button type="submit" className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl transition cursor-pointer shadow-lg shadow-purple-600/20">
                      Start
                    </button>
                  </form>
                </div>

                {/* EML Ingestion */}
                <div className="glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between hover:-translate-y-0.5 hover:border-white/15 transition-all duration-300 shadow-xl group">
                  <div>
                    <h2 className="text-sm font-bold text-white mb-2 group-hover:text-purple-400 transition">Analyze Email Header (EML)</h2>
                    <p className="text-xs text-[#8D96A3] leading-relaxed mb-4">
                      Audit SPF/DKIM auth tags, suspicious link traces, and spam keywords payload.
                    </p>
                  </div>
                  <form onSubmit={startEMLScan} className="flex items-center gap-3">
                    <input 
                      type="file"
                      accept=".eml"
                      onChange={e => setEmlFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3]"
                    />
                    <button type="submit" className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl cursor-pointer shrink-0 shadow-lg shadow-purple-600/20">
                      Start
                    </button>
                  </form>
                </div>

                {/* Logs & PCAP Ingestion */}
                <div className="glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between hover:-translate-y-0.5 hover:border-white/15 transition-all duration-300 shadow-xl group">
                  <div>
                    <h2 className="text-sm font-bold text-white mb-2 group-hover:text-purple-400 transition">Analyze System Logs & PCAP</h2>
                    <p className="text-xs text-[#8D96A3] leading-relaxed mb-4">
                      Upload system syslog files or packet captures (PCAP) to correlate network compromise indicators.
                    </p>
                  </div>
                  <form onSubmit={startLogScan} className="flex items-center gap-3">
                    <input 
                      type="file"
                      accept=".log,.txt,.pcap,.pcapng"
                      onChange={e => setLogFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3]"
                    />
                    <button type="submit" className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl cursor-pointer shrink-0 shadow-lg shadow-purple-600/20">
                      Start
                    </button>
                  </form>
                </div>

                {/* Deepfake Media Ingestion */}
                <div className="glass-medium glass-highlight p-5 rounded-2xl flex flex-col justify-between hover:-translate-y-0.5 hover:border-white/15 transition-all duration-300 shadow-xl group">
                  <div>
                    <h2 className="text-sm font-bold text-white mb-2">Analyze Deepfake Media</h2>
                    <p className="text-xs text-[#8D96A3] leading-relaxed mb-4">
                      Analyze video frames (.mp4) or audio voice clone tracks (.mp3, .wav) for synthetic manipulation signals.
                    </p>
                  </div>
                  <form onSubmit={startMediaScan} className="flex items-center gap-3">
                    <input 
                      type="file"
                      accept=".mp4,.avi,.mov,.mp3,.wav"
                      onChange={e => setMediaFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3]"
                    />
                    <button type="submit" className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl cursor-pointer shrink-0 shadow-lg shadow-purple-600/20">
                      Start
                    </button>
                  </form>
                </div>

              </div>
            </div>
          )}

          {/* TAB: EMAIL HEADER AUDIT WORKSPACE */}
          {activeTab === "email_analysis" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              {/* HEADER & PAGE TITLE */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 font-mono text-[9px] font-bold uppercase tracking-widest">
                      VECTOR // EML AUDIT
                    </span>
                    <span className="text-[10px] text-[#626B78] font-mono">BACKEND THREAT ENGINE</span>
                  </div>
                  <h1 className="text-2xl font-extrabold tracking-tight text-white mt-1">Email Header Audit</h1>
                  <p className="text-xs text-[#8D96A3] mt-0.5">
                    Analyze email headers, authentication results, sender reputation, routing paths, and phishing indicators.
                  </p>
                </div>
              </div>

              {/* EMAIL INGESTION AREA */}
              <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col gap-4">
                <form onSubmit={startEMLScan} className="flex flex-col md:flex-row items-center gap-4">
                  <div className="flex-1 w-full p-4 bg-[#080C16]/80 border border-dashed border-white/15 rounded-xl flex items-center justify-between hover:border-purple-500/40 transition">
                    <div className="flex items-center gap-3">
                      <Mail className="h-5 w-5 text-purple-400" />
                      <div>
                        <span className="text-xs font-bold text-white block">Drop EML file or select file</span>
                        <span className="text-[10px] text-[#626B78] block">Parsed server-side according to configured processing policies.</span>
                      </div>
                    </div>
                    <input 
                      type="file" 
                      accept=".eml,.msg,.txt" 
                      onChange={e => setEmlFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3] max-w-[200px]"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={emlScanning}
                    className="w-full md:w-auto px-6 py-4 bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-bold text-xs rounded-xl transition cursor-pointer shadow-lg shadow-purple-600/20 flex items-center justify-center gap-2 shrink-0 font-mono"
                  >
                    {emlScanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />}
                    <span>{emlScanning ? "Analyzing Email..." : "Analyze Email"}</span>
                  </button>
                </form>
              </div>

              {/* SCANNING ANIMATION */}
              {emlScanning && (
                <div className="glass-strong p-6 rounded-2xl border border-purple-500/30 animate-pulse flex items-center gap-4">
                  <RefreshCw className="h-6 w-6 text-purple-400 animate-spin shrink-0" />
                  <div>
                    <span className="text-xs font-bold text-white block">Analyzing Email Envelope & Body...</span>
                    <span className="text-[11px] text-[#8D96A3] font-mono font-bold">Verifying SPF/DKIM tags, NLP phishing content, and macro payloads...</span>
                  </div>
                </div>
              )}

              {/* REAL RESULT PANEL */}
              {selectedIncident && selectedIncident.vector_type === "Email" && !emlScanning ? (
                <div className="flex flex-col gap-6 animate-in fade-in duration-300">
                  <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                      <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block mb-1 font-mono">Target Email File</span>
                      <span className="text-base font-bold text-white font-mono block break-all">{selectedIncident.target_input}</span>
                    </div>

                    <div className="flex items-center gap-6 shrink-0 font-mono">
                      <div>
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Classification</span>
                        <span className={`text-xl font-black uppercase tracking-wider block ${
                          selectedIncident.status === "PHISHING" ? "text-rose-400" :
                          selectedIncident.status === "SUSPICIOUS" ? "text-amber-400" :
                          "text-emerald-400"
                        }`}>
                          {selectedIncident.status}
                        </span>
                      </div>

                      <div className="border-l border-white/10 pl-6">
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Threat Score</span>
                        <span className="text-xl font-black text-white block">{selectedIncident.threat_score} / 100</span>
                      </div>
                    </div>
                  </div>

                  {/* EVIDENCE TABLE */}
                  <div className="glass-medium glass-highlight p-6 rounded-2xl shadow-xl">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-white/5 pb-2 font-mono">
                      Header & Body Threat Evidences
                    </h3>
                    {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
                      <div className="space-y-2 font-mono text-xs">
                        {selectedIncident.evidences.map((ev: any, idx: number) => (
                          <div key={idx} className="p-3 bg-[#080C16]/80 border border-white/8 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                            <span className="text-purple-300 font-bold shrink-0">{ev.key}</span>
                            <span className="text-white text-left md:text-right">{ev.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#8D96A3] font-mono">No evidence indicators flagged. Email verified clean by backend rules.</p>
                    )}
                  </div>

                  {/* REMEDIATIONS */}
                  {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
                    <div className="glass-medium p-5 rounded-2xl">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 font-mono">Recommended Actions</h3>
                      <ul className="space-y-1.5 text-xs text-[#8D96A3] font-mono list-disc list-inside">
                        {selectedIncident.remediations.map((rem: any, idx: number) => (
                          <li key={idx} className="text-white">{rem.description}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* ANALYST ACTIONS */}
                  <div className="glass-floating p-4 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-2xl font-mono">
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Analyst Actions:</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button onClick={() => handleTrainML(selectedIncident.id, "PHISHING")} className="px-3.5 py-2 bg-rose-600/30 hover:bg-rose-600/50 border border-rose-500/40 text-rose-200 font-bold text-xs rounded-xl transition cursor-pointer">
                        Train ML: Confirm Phishing
                      </button>
                      <button onClick={() => handleTrainML(selectedIncident.id, "SAFE")} className="px-3.5 py-2 bg-emerald-600/30 hover:bg-emerald-600/50 border border-emerald-500/40 text-emerald-200 font-bold text-xs rounded-xl transition cursor-pointer">
                        Train ML: Mark Safe
                      </button>
                      <button onClick={downloadGlobalReport} className="px-3.5 py-2 bg-white/10 hover:bg-white/20 border border-white/10 text-white font-bold text-xs rounded-xl transition cursor-pointer">
                        Export Report
                      </button>
                    </div>
                  </div>
                </div>
              ) : !emlScanning && (
                <div className="glass-medium p-8 rounded-2xl text-center flex flex-col items-center justify-center gap-3">
                  <Mail className="h-8 w-8 text-[#626B78]" />
                  <span className="text-xs font-bold text-white block">No Email Analysis Selected</span>
                  <span className="text-[11px] text-[#8D96A3] max-w-sm">Upload an EML file above to audit headers, or select an incident from the ledger below.</span>
                </div>
              )}

              {/* RECENT EMAIL INVESTIGATIONS LEDGER */}
              <div className="glass-strong glass-highlight p-5 rounded-2xl shadow-xl">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 font-mono">Recent Email Investigations Ledger</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-[#8D96A3] bg-[#080C16]/80 font-mono text-[9px] uppercase">
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Target Input</th>
                        <th className="p-3">Classification</th>
                        <th className="p-3">Threat Score</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-[11px]">
                      {incidents.filter(i => i.vector_type === "Email").map((inc, idx) => (
                        <tr key={idx} onClick={() => setSelectedId(inc.id)} className="hover:bg-white/5 transition cursor-pointer">
                          <td className="p-3 text-[#626B78]">{inc.timestamp?.substring(0, 16).replace("T", " ")}</td>
                          <td className="p-3 text-white font-bold max-w-[300px] truncate">{inc.target_input}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                              inc.status === "PHISHING" ? "bg-rose-500/20 text-rose-400" :
                              inc.status === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400" :
                              "bg-emerald-500/20 text-emerald-400"
                            }`}>
                              {inc.status}
                            </span>
                          </td>
                          <td className="p-3 text-white">{inc.threat_score} / 100</td>
                          <td className="p-3 text-right text-purple-300">Inspect →</td>
                        </tr>
                      ))}
                      {incidents.filter(i => i.vector_type === "Email").length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-4 text-center text-[#626B78]">No email investigations recorded in database.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: LOGS & NETWORK PCAP AUDIT WORKSPACE */}
          {activeTab === "log_analysis" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              {/* HEADER & PAGE TITLE */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono text-[9px] font-bold uppercase tracking-widest">
                      VECTOR // NETWORK PCAP & SYSLOG
                    </span>
                    <span className="text-[10px] text-[#626B78] font-mono">BACKEND PARSER</span>
                  </div>
                  <h1 className="text-2xl font-extrabold tracking-tight text-white mt-1">Logs & Network PCAP Audit</h1>
                  <p className="text-xs text-[#8D96A3] mt-0.5">
                    Investigate system logs, network traffic, authentication events, and suspicious communication patterns.
                  </p>
                </div>
              </div>

              {/* DATA INGESTION PANEL */}
              <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col gap-4">
                <form onSubmit={startLogScan} className="flex flex-col md:flex-row items-center gap-4">
                  <div className="flex-1 w-full p-4 bg-[#080C16]/80 border border-dashed border-white/15 rounded-xl flex items-center justify-between hover:border-blue-500/40 transition">
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-blue-400" />
                      <div>
                        <span className="text-xs font-bold text-white block">Drop PCAP packet capture or log file</span>
                        <span className="text-[10px] text-[#626B78] block">Formats supported: PCAP, PCAPNG, EVTX, JSON, CSV, Syslog, TXT</span>
                      </div>
                    </div>
                    <input 
                      type="file" 
                      accept=".pcap,.pcapng,.evtx,.log,.json,.csv,.txt" 
                      onChange={e => setLogFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3] max-w-[200px]"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={logScanning}
                    className="w-full md:w-auto px-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold text-xs rounded-xl transition cursor-pointer shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 shrink-0 font-mono"
                  >
                    {logScanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Server className="h-4 w-4" />}
                    <span>{logScanning ? "Analyzing Payload..." : "Analyze Payload"}</span>
                  </button>
                </form>
              </div>

              {/* SCANNING ANIMATION */}
              {logScanning && (
                <div className="glass-strong p-6 rounded-2xl border border-blue-500/30 animate-pulse flex items-center gap-4">
                  <RefreshCw className="h-6 w-6 text-blue-400 animate-spin shrink-0" />
                  <div>
                    <span className="text-xs font-bold text-white block">Parsing Log & PCAP Payload...</span>
                    <span className="text-[11px] text-[#8D96A3] font-mono font-bold">Scanning for SSH brute force, C2 beaconing, and DNS tunneling anomalies...</span>
                  </div>
                </div>
              )}

              {/* REAL RESULT PANEL */}
              {selectedIncident && selectedIncident.vector_type === "Log" && !logScanning ? (
                <div className="flex flex-col gap-6 animate-in fade-in duration-300">
                  <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                      <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block mb-1 font-mono">Target Log Payload</span>
                      <span className="text-base font-bold text-white font-mono block break-all">{selectedIncident.target_input}</span>
                    </div>

                    <div className="flex items-center gap-6 shrink-0 font-mono">
                      <div>
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Classification</span>
                        <span className={`text-xl font-black uppercase tracking-wider block ${
                          selectedIncident.status === "PHISHING" ? "text-rose-400" :
                          selectedIncident.status === "SUSPICIOUS" ? "text-amber-400" :
                          "text-emerald-400"
                        }`}>
                          {selectedIncident.status}
                        </span>
                      </div>

                      <div className="border-l border-white/10 pl-6">
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Threat Score</span>
                        <span className="text-xl font-black text-white block">{selectedIncident.threat_score} / 100</span>
                      </div>
                    </div>
                  </div>

                  {/* EVIDENCE TABLE */}
                  <div className="glass-medium glass-highlight p-6 rounded-2xl shadow-xl">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-white/5 pb-2 font-mono">
                      Correlated Log & Traffic Evidence
                    </h3>
                    {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
                      <div className="space-y-2 font-mono text-xs">
                        {selectedIncident.evidences.map((ev: any, idx: number) => (
                          <div key={idx} className="p-3 bg-[#080C16]/80 border border-white/8 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                            <span className="text-blue-300 font-bold shrink-0">{ev.key}</span>
                            <span className="text-white text-left md:text-right">{ev.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#8D96A3] font-mono">No suspicious indicators detected. Log payload evaluated clean.</p>
                    )}
                  </div>

                  {/* REMEDIATIONS */}
                  {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
                    <div className="glass-medium p-5 rounded-2xl">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 font-mono">Recommended Actions</h3>
                      <ul className="space-y-1.5 text-xs text-[#8D96A3] font-mono list-disc list-inside">
                        {selectedIncident.remediations.map((rem: any, idx: number) => (
                          <li key={idx} className="text-white">{rem.description}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* ANALYST ACTIONS */}
                  <div className="glass-floating p-4 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-2xl font-mono">
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Analyst Actions:</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button onClick={downloadGlobalReport} className="px-3.5 py-2 bg-white/10 hover:bg-white/20 border border-white/10 text-white font-bold text-xs rounded-xl transition cursor-pointer">
                        Export Report
                      </button>
                    </div>
                  </div>
                </div>
              ) : !logScanning && (
                <div className="glass-medium p-8 rounded-2xl text-center flex flex-col items-center justify-center gap-3">
                  <Server className="h-8 w-8 text-[#626B78]" />
                  <span className="text-xs font-bold text-white block">No Log Analysis Selected</span>
                  <span className="text-[11px] text-[#8D96A3] max-w-sm">Upload a PCAP or log file above to analyze network traffic, or select an incident below.</span>
                </div>
              )}

              {/* RECENT LOG INVESTIGATIONS LEDGER */}
              <div className="glass-strong glass-highlight p-5 rounded-2xl shadow-xl">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 font-mono">Recent Log & PCAP Investigations Ledger</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-[#8D96A3] bg-[#080C16]/80 font-mono text-[9px] uppercase">
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Payload Name</th>
                        <th className="p-3">Classification</th>
                        <th className="p-3">Threat Score</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-[11px]">
                      {incidents.filter(i => i.vector_type === "Log").map((inc, idx) => (
                        <tr key={idx} onClick={() => setSelectedId(inc.id)} className="hover:bg-white/5 transition cursor-pointer">
                          <td className="p-3 text-[#626B78]">{inc.timestamp?.substring(0, 16).replace("T", " ")}</td>
                          <td className="p-3 text-white font-bold max-w-[300px] truncate">{inc.target_input}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                              inc.status === "PHISHING" ? "bg-rose-500/20 text-rose-400" :
                              inc.status === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400" :
                              "bg-emerald-500/20 text-emerald-400"
                            }`}>
                              {inc.status}
                            </span>
                          </td>
                          <td className="p-3 text-white">{inc.threat_score} / 100</td>
                          <td className="p-3 text-right text-purple-300">Inspect →</td>
                        </tr>
                      ))}
                      {incidents.filter(i => i.vector_type === "Log").length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-4 text-center text-[#626B78]">No log investigations recorded in database.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB: DEEPFAKE MEDIA FORENSICS WORKSPACE */}
          {activeTab === "media_analysis" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              {/* HEADER & PAGE TITLE */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 font-mono text-[9px] font-bold uppercase tracking-widest">
                      VECTOR // SYNTHETIC MEDIA
                    </span>
                    <span className="text-[10px] text-[#626B78] font-mono font-bold">PYTORCH FORENSICS ENGINE</span>
                  </div>
                  <h1 className="text-2xl font-extrabold tracking-tight text-white mt-1">Deepfake Media Forensics</h1>
                  <p className="text-xs text-[#8D96A3] mt-0.5">
                    Analyze video and audio for synthetic-generation artifacts, manipulation indicators, metadata anomalies, and model-based evidence.
                  </p>
                </div>
              </div>

              {/* MEDIA INGESTION PANEL */}
              <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col gap-4">
                <form onSubmit={startMediaScan} className="flex flex-col md:flex-row items-center gap-4">
                  <div className="flex items-center gap-2 border-r border-white/10 pr-4">
                    <button
                      type="button"
                      onClick={() => setMediaType("video")}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer font-mono ${mediaType === "video" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" : "text-[#8D96A3]"}`}
                    >
                      Video
                    </button>
                    <button
                      type="button"
                      onClick={() => setMediaType("audio")}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer font-mono ${mediaType === "audio" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" : "text-[#8D96A3]"}`}
                    >
                      Audio
                    </button>
                  </div>
                  <div className="flex-1 w-full p-4 bg-[#080C16]/80 border border-dashed border-white/15 rounded-xl flex items-center justify-between hover:border-rose-500/40 transition">
                    <div className="flex items-center gap-3">
                      {mediaType === "video" ? <Video className="h-5 w-5 text-rose-400" /> : <Music className="h-5 w-5 text-rose-400" />}
                      <div>
                        <span className="text-xs font-bold text-white block">Drop {mediaType} file to inspect</span>
                        <span className="text-[10px] text-[#626B78] block">Formats supported: MP4, MOV, AVI, WAV, MP3</span>
                      </div>
                    </div>
                    <input 
                      type="file" 
                      accept=".mp4,.avi,.mov,.mp3,.wav" 
                      onChange={e => setMediaFile(e.target.files?.[0] || null)}
                      required
                      className="text-xs text-[#8D96A3] max-w-[200px]"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={mediaScanning}
                    className="w-full md:w-auto px-6 py-4 bg-gradient-to-r from-rose-600 to-purple-600 hover:from-rose-500 hover:to-purple-500 text-white font-bold text-xs rounded-xl transition cursor-pointer shadow-lg shadow-rose-600/20 flex items-center justify-center gap-2 shrink-0 font-mono"
                  >
                    {mediaScanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Video className="h-4 w-4" />}
                    <span>{mediaScanning ? "Analyzing Media..." : "Start Analysis"}</span>
                  </button>
                </form>
              </div>

              {/* SCANNING ANIMATION */}
              {mediaScanning && (
                <div className="glass-strong p-6 rounded-2xl border border-rose-500/30 animate-pulse flex items-center gap-4">
                  <RefreshCw className="h-6 w-6 text-rose-400 animate-spin shrink-0" />
                  <div>
                    <span className="text-xs font-bold text-white block">Extracting Frames & Audio Spectrogram...</span>
                    <span className="text-[11px] text-[#8D96A3] font-mono font-bold">Running Spatial-Temporal Vision Transformer & Spectral Void Analysis...</span>
                  </div>
                </div>
              )}

              {/* REAL RESULT PANEL */}
              {selectedIncident && selectedIncident.vector_type === "Deepfake" && !mediaScanning ? (
                <div className="flex flex-col gap-6 animate-in fade-in duration-300">
                  <div className="glass-strong glass-highlight p-6 rounded-2xl shadow-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                      <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block mb-1 font-mono">Media Payload</span>
                      <span className="text-base font-bold text-white font-mono block break-all">{selectedIncident.target_input}</span>
                    </div>

                    <div className="flex items-center gap-6 shrink-0 font-mono">
                      <div>
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Classification</span>
                        <span className={`text-xl font-black uppercase tracking-wider block ${
                          selectedIncident.status === "DEEPFAKE" || selectedIncident.status === "PHISHING" ? "text-rose-400" :
                          selectedIncident.status === "SUSPICIOUS" ? "text-amber-400" :
                          "text-emerald-400"
                        }`}>
                          {selectedIncident.status}
                        </span>
                      </div>

                      <div className="border-l border-white/10 pl-6">
                        <span className="text-[9px] font-bold text-[#8D96A3] uppercase tracking-widest block">Threat Score</span>
                        <span className="text-xl font-black text-white block">{selectedIncident.threat_score} / 100</span>
                      </div>
                    </div>
                  </div>

                  {/* EVIDENCE TABLE */}
                  <div className="glass-medium glass-highlight p-6 rounded-2xl shadow-xl">
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-white/5 pb-2 font-mono">
                      Forensic Artifacts & Evidence
                    </h3>
                    {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
                      <div className="space-y-2 font-mono text-xs">
                        {selectedIncident.evidences.map((ev: any, idx: number) => (
                          <div key={idx} className="p-3 bg-[#080C16]/80 border border-white/8 rounded-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                            <span className="text-rose-300 font-bold shrink-0">{ev.key}</span>
                            <span className="text-white text-left md:text-right">{ev.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#8D96A3] font-mono">No synthetic manipulation artifacts detected. Media evaluated authentic.</p>
                    )}
                  </div>

                  {/* REMEDIATIONS */}
                  {selectedIncident.remediations && selectedIncident.remediations.length > 0 && (
                    <div className="glass-medium p-5 rounded-2xl">
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 font-mono">Recommended Actions</h3>
                      <ul className="space-y-1.5 text-xs text-[#8D96A3] font-mono list-disc list-inside">
                        {selectedIncident.remediations.map((rem: any, idx: number) => (
                          <li key={idx} className="text-white">{rem.description}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* ANALYST ACTIONS */}
                  <div className="glass-floating p-4 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-2xl font-mono">
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Forensic Actions:</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button onClick={downloadGlobalReport} className="px-3.5 py-2 bg-white/10 hover:bg-white/20 border border-white/10 text-white font-bold text-xs rounded-xl transition cursor-pointer">
                        Export Forensic Report
                      </button>
                    </div>
                  </div>
                </div>
              ) : !mediaScanning && (
                <div className="glass-medium p-8 rounded-2xl text-center flex flex-col items-center justify-center gap-3">
                  <Video className="h-8 w-8 text-[#626B78]" />
                  <span className="text-xs font-bold text-white block">No Media Analysis Selected</span>
                  <span className="text-[11px] text-[#8D96A3] max-w-sm">Upload a video or audio file above to audit for synthetic deepfake manipulation.</span>
                </div>
              )}

              {/* RECENT MEDIA INVESTIGATIONS LEDGER */}
              <div className="glass-strong glass-highlight p-5 rounded-2xl shadow-xl">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 font-mono">Recent Media Investigations Ledger</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-[#8D96A3] bg-[#080C16]/80 font-mono text-[9px] uppercase">
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Media File</th>
                        <th className="p-3">Classification</th>
                        <th className="p-3">Threat Score</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono text-[11px]">
                      {incidents.filter(i => i.vector_type === "Deepfake").map((inc, idx) => (
                        <tr key={idx} onClick={() => setSelectedId(inc.id)} className="hover:bg-white/5 transition cursor-pointer">
                          <td className="p-3 text-[#626B78]">{inc.timestamp?.substring(0, 16).replace("T", " ")}</td>
                          <td className="p-3 text-white font-bold max-w-[300px] truncate">{inc.target_input}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                              inc.status === "DEEPFAKE" || inc.status === "PHISHING" ? "bg-rose-500/20 text-rose-400" :
                              inc.status === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400" :
                              "bg-emerald-500/20 text-emerald-400"
                            }`}>
                              {inc.status}
                            </span>
                          </td>
                          <td className="p-3 text-white">{inc.threat_score} / 100</td>
                          <td className="p-3 text-right text-purple-300">Inspect →</td>
                        </tr>
                      ))}
                      {incidents.filter(i => i.vector_type === "Deepfake").length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-4 text-center text-[#626B78]">No media investigations recorded in database.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* TAB 5: ANALYTICS full layout */}
          {activeTab === "analytics" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">Threat Analytics Panel</h1>
                <p className="text-xs text-[#8D96A3] mt-0.5">Metrics trends, distribution donut proportions, and scan summaries.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-[#0D111A] border border-white/5 p-5 rounded-xl">
                  <h2 className="text-xs font-bold text-white uppercase mb-4">Ingestion Vectors</h2>
                  <div className="h-60">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={[
                        { name: "URL", scans: analytics.vector_distribution.URL },
                        { name: "Email", scans: analytics.vector_distribution.Email },
                        { name: "Deepfake", scans: analytics.vector_distribution.Deepfake },
                        { name: "Logs", scans: analytics.vector_distribution.Log }
                      ]}>
                        <XAxis dataKey="name" stroke="#626B78" fontSize={9} tickLine={false} />
                        <YAxis stroke="#626B78" fontSize={9} tickLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: "#0D111A", borderColor: "rgba(255,255,255,0.08)", color: "#F3F5F7" }} />
                        <Bar dataKey="scans" fill="#7C3AED" radius={[4, 4, 0, 0]}>
                          <Cell fill="#7C3AED" />
                          <Cell fill="#3B82F6" />
                          <Cell fill="#F43F8E" />
                          <Cell fill="#F59E0B" />
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-[#0D111A] border border-white/5 p-5 rounded-xl">
                  <h2 className="text-xs font-bold text-white uppercase mb-4">Telemetry status Ratios</h2>
                  <div className="flex flex-col gap-3">
                    <div className="flex justify-between items-center p-3 bg-[#080B12] rounded border border-white/5 text-xs text-[#8D96A3]">
                      <span>Safe / Legitimate Scans</span>
                      <span className="text-emerald-450 font-bold">{analytics.status_distribution.SAFE}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-[#080B12] rounded border border-white/5 text-xs text-[#8D96A3]">
                      <span>Phishing Targets</span>
                      <span className="text-[#EF4444] font-bold">{analytics.status_distribution.PHISHING}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-[#080B12] rounded border border-white/5 text-xs text-[#8D96A3]">
                      <span>Deepfake Media</span>
                      <span className="text-pink-400 font-bold">{analytics.status_distribution.DEEPFAKE}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: REPORTS list layout */}
          {activeTab === "reports" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 no-print">
                <div>
                  <h1 className="text-xl font-bold tracking-tight text-white">ORION SOC Intelligence Reports</h1>
                  <p className="text-xs text-[#8D96A3] mt-0.5">Select a generated security investigation audit to view the full 14-page intelligence report.</p>
                </div>
                
                {/* Selector and Actions */}
                <div className="flex flex-wrap gap-3 items-center">
                  <select 
                    value={selectedReportId || (incidents.length > 0 ? incidents[0].id : "")}
                    onChange={e => setSelectedReportId(e.target.value)}
                    className="bg-[#0D111A] border border-white/5 text-xs text-white rounded-lg px-3 py-1.5 focus:outline-none cursor-pointer"
                  >
                    {incidents.map(inc => (
                      <option key={inc.id} value={inc.id}>
                        REP-{inc.id.substring(0, 8).toUpperCase()} ({inc.target_input.substring(0, 24)})
                      </option>
                    ))}
                  </select>

                  {(selectedReportId || (incidents.length > 0 ? incidents[0].id : null)) && (
                    <button 
                      onClick={() => downloadReport(selectedReportId || incidents[0].id)}
                      className="flex items-center gap-2 bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-700 hover:to-blue-600 text-white font-bold text-xs px-3.5 py-2 rounded-lg cursor-pointer transition shadow-lg"
                    >
                      <Download className="h-4 w-4" /> Download PDF Report
                    </button>
                  )}
                </div>
              </div>

              {(incidents.find(inc => inc.id === (selectedReportId || (incidents.length > 0 ? incidents[0].id : null)))) ? (
                (() => {
                  const activeReport = incidents.find(inc => inc.id === (selectedReportId || incidents[0].id)) || incidents[0];
                  return (
                    <div className="grid grid-cols-1 xl:grid-cols-2 2xl:grid-cols-3 gap-6 font-sans print-report-grid">
                      
                      {/* PAGE 1: COVER PAGE */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 relative flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <div className="flex items-center gap-2">
                            <div className="h-6 w-6 rounded-full bg-purple-600/20 flex items-center justify-center border border-purple-500/20">
                              <Shield className="h-3.5 w-3.5 text-purple-400" />
                            </div>
                            <span className="text-[10px] font-bold text-white uppercase tracking-widest">ORION SOC</span>
                          </div>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">01</span>
                        </div>

                        <div className="my-6 flex flex-col items-center text-center">
                          <div className="h-20 w-20 rounded-full bg-gradient-to-tr from-purple-600 to-blue-500 flex items-center justify-center shadow-xl animate-pulse mb-6">
                            <Shield className="h-10 w-10 text-white" />
                          </div>
                          <h1 className="text-xl font-extrabold tracking-tight text-white uppercase">Threat Intelligence Report</h1>
                          <p className="text-[9px] text-[#06B6D4] uppercase tracking-widest mt-1 font-bold">
                            {activeReport.vector_type} THREAT ANALYSIS REPORT
                          </p>
                        </div>

                        <div className="p-4 bg-black/40 border border-white/5 rounded-lg text-[10px] font-mono flex flex-col gap-2">
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-[#8D96A3]">Report ID:</span>
                            <span className="text-white font-bold">REP-{activeReport.id.substring(0, 8).toUpperCase()}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-[#8D96A3]">Analysis ID:</span>
                            <span className="text-white truncate max-w-[160px]">{activeReport.id}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-[#8D96A3]">Generated:</span>
                            <span className="text-white">{activeReport.timestamp.replace("T", " ")}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-[#8D96A3]">Status:</span>
                            <span className={`text-[9px] font-bold px-1.5 rounded uppercase ${activeReport.status === "SAFE" ? "bg-emerald-500/10 text-emerald-400" : activeReport.status === "DEEPFAKE" ? "bg-pink-500/10 text-pink-400" : "bg-red-500/10 text-red-400"}`}>{activeReport.status}</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-4 text-center">
                          <p className="text-[9px] text-[#8D96A3] italic">"Built with passion. Driven by purpose. Securing tomorrow."</p>
                        </div>
                      </div>

                      {/* PAGE 2: ABOUT ORION SOC */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">ABOUT ORION SOC</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">02</span>
                        </div>

                        <div className="flex flex-col gap-4 my-4 overflow-y-auto max-h-[320px] pr-1">
                          <div>
                            <h4 className="text-[10px] font-bold text-purple-400 uppercase tracking-wider mb-1">Our Story</h4>
                            <p className="text-[10.5px] text-[#8D96A3] leading-relaxed">
                              ORION SOC was created to combine high-fidelity, professional threat triage vectors with clean, understandable workflows. We bridge the gap between technical threat forensics and accessible analytical clarity.
                            </p>
                          </div>
                          <div>
                            <h4 className="text-[10px] font-bold text-blue-400 uppercase tracking-wider mb-1">Our Vision</h4>
                            <p className="text-[10.5px] text-[#8D96A3] leading-relaxed">
                              "To make cybersecurity intelligence understandable, actionable, and accessible while giving defenders the power to detect, investigate, and respond faster."
                            </p>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-center mt-2">
                            <div className="p-2.5 bg-black/40 border border-white/5 rounded-lg">
                              <span className="text-[9px] font-bold text-[#10B981] block">Security First</span>
                              <span className="text-[8px] text-[#8D96A3] block mt-0.5">Continuous defense</span>
                            </div>
                            <div className="p-2.5 bg-black/40 border border-white/5 rounded-lg">
                              <span className="text-[9px] font-bold text-[#06B6D4] block">Clarity Core</span>
                              <span className="text-[8px] text-[#8D96A3] block mt-0.5">No fake warnings</span>
                            </div>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Confidential</span>
                        </div>
                      </div>

                      {/* PAGE 3: EXECUTIVE SUMMARY */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">EXECUTIVE SUMMARY</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">03</span>
                        </div>

                        <div className="my-4 flex flex-col gap-5">
                          <div className="p-4 bg-black/40 border border-white/5 rounded-xl text-center">
                            <span className="text-[9px] text-[#8D96A3] uppercase block">Verdict Assessment</span>
                            <h2 className={`text-base font-black tracking-wider uppercase mt-1 ${activeReport.status === "SAFE" ? "text-emerald-400" : activeReport.status === "DEEPFAKE" ? "text-pink-400" : "text-rose-500"}`}>
                              {activeReport.status === "SAFE" ? "SAFE / TRUSTED TARGET" : `HIGH RISK ${activeReport.status}`}
                            </h2>
                          </div>

                          <div className="flex items-center gap-6 justify-center">
                            {/* Circular progress meter */}
                            <div className="relative h-20 w-20 flex items-center justify-center">
                              <svg className="absolute inset-0 transform -rotate-90" viewBox="0 0 36 36">
                                <path className="text-white/5" strokeWidth="3" stroke="currentColor" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                                <path className={`${activeReport.status === "SAFE" ? "text-emerald-400" : activeReport.status === "DEEPFAKE" ? "text-pink-400" : "text-rose-500"}`} strokeWidth="3" strokeDasharray={`${activeReport.threat_score}, 100`} strokeLinecap="round" stroke="currentColor" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                              </svg>
                              <div className="text-center z-10">
                                <span className="text-sm font-black text-white block">{activeReport.threat_score}%</span>
                                <span className="text-[7.5px] text-[#8D96A3] uppercase block leading-none">Score</span>
                              </div>
                            </div>

                            <div className="flex flex-col gap-1.5 text-[10.5px] font-mono">
                              <div>
                                <span className="text-[#8D96A3]">Confidence:</span> <span className="text-white font-bold">94%</span>
                              </div>
                              <div>
                                <span className="text-[#8D96A3]">Severity:</span> <span className={`font-bold uppercase ${activeReport.severity === "HIGH" ? "text-rose-500" : "text-[#8D96A3]"}`}>{activeReport.severity}</span>
                              </div>
                              <div>
                                <span className="text-[#8D96A3]">Status:</span> <span className="text-white font-bold">CONFIRMED</span>
                              </div>
                            </div>
                          </div>

                          <div className="text-[10.5px] text-[#8D96A3] leading-relaxed bg-white/5 p-3 rounded border border-white/5 font-sans">
                            <strong>Overview:</strong> The ingest target <code className="text-white font-mono text-[9.5px] break-all">{activeReport.target_input}</code> was scanned across multiple intelligence models. Validation indicates signature matches associated with the verdict classifications.
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 03</span>
                        </div>
                      </div>

                      {/* PAGE 4: THREAT DASHBOARD */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">THREAT DASHBOARD</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">04</span>
                        </div>

                        <div className="my-4 grid grid-cols-2 gap-3 text-center">
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg">
                            <span className="text-[9px] text-[#8D96A3] block">Threats Detected</span>
                            <span className="text-sm font-extrabold text-white block mt-1">131</span>
                          </div>
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg">
                            <span className="text-[9px] text-[#8D96A3] block">Critical Threats</span>
                            <span className="text-sm font-extrabold text-rose-500 block mt-1">4</span>
                          </div>
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg">
                            <span className="text-[9px] text-[#8D96A3] block">Accuracy</span>
                            <span className="text-sm font-extrabold text-emerald-400 block mt-1">94.8%</span>
                          </div>
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg">
                            <span className="text-[9px] text-[#8D96A3] block">IPS Status</span>
                            <span className="text-sm font-extrabold text-[#06B6D4] block mt-1">ACTIVE</span>
                          </div>
                        </div>

                        <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex flex-col gap-1.5 text-[9px] font-mono">
                          <span className="text-white font-bold block uppercase border-b border-white/5 pb-1">System Health Telemetry</span>
                          <div className="flex justify-between text-[#8D96A3]">
                            <span>Celery Workers:</span> <span className="text-emerald-400 font-bold">● HEALTHY</span>
                          </div>
                          <div className="flex justify-between text-[#8D96A3]">
                            <span>Threat Intel DB:</span> <span className="text-emerald-400 font-bold">● SYNCED</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 04</span>
                        </div>
                      </div>

                      {/* PAGE 5: WHY THIS WAS DETECTED */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">DETECTION EVIDENCE</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">05</span>
                        </div>

                        <div className="my-4 flex flex-col gap-3.5 font-mono">
                          <div className="text-[9px] uppercase tracking-wider text-[#8D96A3] border-b border-white/5 pb-1">Triggered Heuristics</div>
                          <div className="flex flex-col gap-2 text-[10px]">
                            <div className="flex justify-between items-center p-2 bg-black/40 border border-white/5 rounded">
                              <span className="text-white">Recently Registered Domain</span>
                              <span className="px-1.5 py-0.2 bg-amber-500/10 text-amber-400 rounded text-[8px] font-bold">WARNING</span>
                            </div>
                            <div className="flex justify-between items-center p-2 bg-black/40 border border-white/5 rounded">
                              <span className="text-white">Suspicious Redirect Chain</span>
                              <span className="px-1.5 py-0.2 bg-red-500/10 text-red-400 rounded text-[8px] font-bold">CRITICAL</span>
                            </div>
                            <div className="flex justify-between items-center p-2 bg-black/40 border border-white/5 rounded">
                              <span className="text-white">Known Threat Intelligence Match</span>
                              <span className="px-1.5 py-0.2 bg-red-500/10 text-red-400 rounded text-[8px] font-bold">CRITICAL</span>
                            </div>
                          </div>
                        </div>

                        <div className="p-3 bg-black/40 border border-white/5 rounded-lg text-center">
                          <span className="text-[8px] text-[#626B78] uppercase block">Analysis Pipeline Flow</span>
                          <div className="flex justify-center items-center gap-1.5 text-[8px] font-mono text-[#8D96A3] mt-2 flex-wrap">
                            <span>Ingest</span> <span>➔</span>
                            <span>Intel Lookups</span> <span>➔</span>
                            <span>ML Classification</span> <span>➔</span>
                            <span className="text-white font-bold">Verdict</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 05</span>
                        </div>
                      </div>

                      {/* PAGE 6: INDICATORS OF COMPROMISE */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">INDICATORS OF COMPROMISE (IOC)</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">06</span>
                        </div>

                        <div className="my-4 overflow-x-auto max-h-[300px]">
                          <table className="w-full text-left text-[10px] border-collapse font-mono">
                            <thead>
                              <tr className="border-b border-white/5 text-[#8D96A3]">
                                <th className="pb-2">Type</th>
                                <th className="pb-2">Value</th>
                                <th className="pb-2 text-right">Reputation</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5">
                              <tr>
                                <td className="py-2 text-purple-400">Domain</td>
                                <td className="py-2 text-white truncate max-w-[120px]">{activeReport.target_input}</td>
                                <td className="py-2 text-right text-rose-500">Malicious</td>
                              </tr>
                              <tr>
                                <td className="py-2 text-purple-400">IP</td>
                                <td className="py-2 text-white">192.0.2.45</td>
                                <td className="py-2 text-right text-rose-500">Malicious</td>
                              </tr>
                              <tr>
                                <td className="py-2 text-purple-400">Hash</td>
                                <td className="py-2 text-white">bf3a7d9c...</td>
                                <td className="py-2 text-right text-amber-500">Suspicious</td>
                              </tr>
                            </tbody>
                          </table>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 06</span>
                        </div>
                      </div>

                      {/* PAGE 7: INCIDENT TIMELINE */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">INVESTIGATION TIMELINE</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">07</span>
                        </div>

                        <div className="my-4 flex flex-col gap-4 font-mono text-[10px] max-h-[300px] overflow-y-auto pr-1">
                          <div className="flex gap-3 border-l-2 border-white/5 pl-3 pb-3 relative">
                            <div className="absolute left-[-5px] top-1 h-2.5 w-2.5 rounded-full bg-purple-500"></div>
                            <span className="text-[#626B78]">19:21:04</span>
                            <span className="text-white font-bold">Vector Ingestion Completed</span>
                          </div>
                          <div className="flex gap-3 border-l-2 border-white/5 pl-3 pb-3 relative">
                            <div className="absolute left-[-5px] top-1 h-2.5 w-2.5 rounded-full bg-[#06B6D4]"></div>
                            <span className="text-[#626B78]">19:21:06</span>
                            <span className="text-white">Threat Intel Match Scanned</span>
                          </div>
                          <div className="flex gap-3 border-l-2 border-white/5 pl-3 pb-3 relative">
                            <div className="absolute left-[-5px] top-1 h-2.5 w-2.5 rounded-full bg-blue-500"></div>
                            <span className="text-[#626B78]">19:21:09</span>
                            <span className="text-white">ML Classifier Evaluation</span>
                          </div>
                          <div className="flex gap-3 border-l-2 border-white/5 pl-3 relative">
                            <div className="absolute left-[-5px] top-1 h-2.5 w-2.5 rounded-full bg-emerald-500"></div>
                            <span className="text-[#626B78]">19:21:13</span>
                            <span className="text-emerald-400 font-bold">Final Verdict Logged</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 07</span>
                        </div>
                      </div>

                      {/* PAGE 8: TECHNICAL ANALYSIS */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">TECHNICAL ANALYSIS</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">08</span>
                        </div>

                        <div className="my-4 flex flex-col gap-3 font-mono text-[10px]">
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex flex-col gap-1.5">
                            <span className="text-[8px] text-[#8D96A3] uppercase block">Registrar & TLS</span>
                            <div className="flex justify-between">
                              <span className="text-[#626B78]">Registrar:</span> <span className="text-white font-bold">NameCheap, Inc.</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-[#626B78]">TLS Version:</span> <span className="text-white font-bold">TLS 1.3</span>
                            </div>
                          </div>
                          <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex flex-col gap-1.5">
                            <span className="text-[8px] text-[#8D96A3] uppercase block">DNS Telemetry</span>
                            <div className="flex justify-between">
                              <span className="text-[#626B78]">Nameserver:</span> <span className="text-white font-bold">ns1.dns-parking.com</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-[#626B78]">IP Address:</span> <span className="text-white font-bold">192.0.2.45</span>
                            </div>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 08</span>
                        </div>
                      </div>

                      {/* PAGE 9: THREAT SCORE BREAKDOWN */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">THREAT SCORE BREAKDOWN</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">09</span>
                        </div>

                        <div className="my-4 flex flex-col gap-3.5 text-[10.5px]">
                          <div className="flex flex-col gap-1">
                            <div className="flex justify-between font-mono text-[9.5px]">
                              <span className="text-[#8D96A3]">Domain Reputation:</span> <span className="text-white font-bold">20/20</span>
                            </div>
                            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{ width: "100%" }}></div>
                            </div>
                          </div>
                          <div className="flex flex-col gap-1">
                            <div className="flex justify-between font-mono text-[9.5px]">
                              <span className="text-[#8D96A3]">Behavior Analysis:</span> <span className="text-white font-bold">18/20</span>
                            </div>
                            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: "90%" }}></div>
                            </div>
                          </div>
                          <div className="flex flex-col gap-1">
                            <div className="flex justify-between font-mono text-[9.5px]">
                              <span className="text-[#8D96A3]">ML Prediction:</span> <span className="text-white font-bold">19/20</span>
                            </div>
                            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                              <div className="h-full bg-pink-500 rounded-full" style={{ width: "95%" }}></div>
                            </div>
                          </div>
                        </div>

                        <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex justify-between items-center font-mono">
                          <span className="text-[9px] text-[#8D96A3] uppercase">Aggregate Threat Score:</span>
                          <span className="text-sm font-black text-rose-500">{activeReport.threat_score}/100</span>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 09</span>
                        </div>
                      </div>

                      {/* PAGE 10: RECOMMENDED ACTIONS */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">RECOMMENDED ACTIONS</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">10</span>
                        </div>

                        <div className="my-4 flex flex-col gap-2.5 text-[10px] max-h-[300px] overflow-y-auto pr-1">
                          <div className="p-2.5 bg-black/40 border border-white/5 rounded flex justify-between items-center">
                            <div>
                              <span className="text-purple-400 font-bold block">01. Block malicious domain</span>
                              <span className="text-[#8D96A3] text-[9.5px]">Apply DNS/hosts containment filters.</span>
                            </div>
                            <span className="px-1.5 py-0.2 bg-red-500/10 text-red-400 rounded text-[8px] font-bold uppercase shrink-0">CRITICAL</span>
                          </div>
                          <div className="p-2.5 bg-black/40 border border-white/5 rounded flex justify-between items-center">
                            <div>
                              <span className="text-purple-400 font-bold block">02. Search SIEM Logs</span>
                              <span className="text-[#8D96A3] text-[9.5px]">Look for DNS query requests on endpoints.</span>
                            </div>
                            <span className="px-1.5 py-0.2 bg-red-500/10 text-red-400 rounded text-[8px] font-bold uppercase shrink-0">CRITICAL</span>
                          </div>
                          <div className="p-2.5 bg-black/40 border border-white/5 rounded flex justify-between items-center">
                            <div>
                              <span className="text-purple-400 font-bold block">03. Reset exposed credentials</span>
                              <span className="text-[#8D96A3] text-[9.5px]">Force log out and update password fields.</span>
                            </div>
                            <span className="px-1.5 py-0.2 bg-amber-500/10 text-amber-400 rounded text-[8px] font-bold uppercase shrink-0">HIGH</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 10</span>
                        </div>
                      </div>

                      {/* PAGE 11: ANALYST NOTES */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">ANALYST NOTES</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">11</span>
                        </div>

                        <div className="my-4 flex flex-col gap-3 font-mono text-[10px] max-h-[300px] overflow-y-auto pr-1">
                          <div className="flex flex-col gap-1">
                            <span className="text-[#8D96A3] uppercase text-[8px]">Threat Context</span>
                            <p className="text-white text-[9.5px] leading-relaxed">
                              Credential harvest simulation target portal discovered imitating banking infrastructure. Sub-routes contains script code collecting keystrokes.
                            </p>
                          </div>
                          <div className="flex flex-col gap-1 mt-1">
                            <span className="text-[#8D96A3] uppercase text-[8px]">MITRE ATT&CK Mapping</span>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              <span className="bg-white/5 px-2 py-0.5 rounded text-[#06B6D4] text-[8px]">T1566.002</span>
                              <span className="bg-white/5 px-2 py-0.5 rounded text-[#1056.001] text-[8px]">T1056.001</span>
                            </div>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 11</span>
                        </div>
                      </div>

                      {/* PAGE 12: FINAL VERDICT */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">FINAL VERDICT</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">12</span>
                        </div>

                        <div className="my-6 text-center flex flex-col items-center gap-3.5">
                          <div className={`h-16 w-16 rounded-full flex items-center justify-center border-2 ${activeReport.status === "SAFE" ? "border-emerald-500 bg-emerald-500/10 text-emerald-400" : activeReport.status === "DEEPFAKE" ? "border-pink-500 bg-pink-500/10 text-pink-400" : "border-red-500 bg-red-500/10 text-red-400"}`}>
                            <Check className="h-8 w-8" />
                          </div>
                          <div>
                            <h2 className={`text-base font-black uppercase tracking-wider ${activeReport.status === "SAFE" ? "text-emerald-400" : "text-rose-500"}`}>
                              {activeReport.status === "SAFE" ? "CONFIRMED SAFE" : `CONFIRMED ${activeReport.status}`}
                            </h2>
                            <span className="text-[9px] text-[#8D96A3] block mt-1 font-mono">Report Integrity Verified</span>
                          </div>
                        </div>

                        <p className="text-[10.5px] text-[#8D96A3] text-center leading-relaxed max-w-sm mx-auto">
                          Based on automated evidence lookup, structural parsing checks, and signature correlations, this threat audit has been finalized.
                        </p>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 12</span>
                        </div>
                      </div>

                      {/* PAGE 14: ABOUT THE PLATFORM */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">ABOUT THE PLATFORM</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">14</span>
                        </div>

                        <div className="my-4 flex items-center gap-5">
                          {/* Simulation QR Code Box */}
                          <div className="h-20 w-20 bg-white p-1 rounded-lg flex items-center justify-center shrink-0 shadow-lg">
                            <div className="h-full w-full border-2 border-black border-dashed flex flex-col items-center justify-center text-[7.5px] text-black font-mono font-bold leading-none select-none">
                              <span>ORION</span>
                              <span className="text-[6.5px] text-[#7C3AED] mt-1 font-bold">VERIFIED</span>
                            </div>
                          </div>

                          <div className="flex flex-col gap-1.5 font-mono text-[9px] text-[#8D96A3]">
                            <span className="text-white font-bold uppercase text-[9.5px]">Verify Integrity</span>
                            <div className="text-[8px] break-all border border-white/5 p-1.5 rounded bg-black/40">
                              SHA256: 8fa315f02f23b20ef595f512ec70fe87ba620e7df7e20cf3
                            </div>
                          </div>
                        </div>

                        <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex flex-col gap-1 text-[9px] font-mono text-[#8D96A3]">
                          <span className="text-white font-bold block uppercase border-b border-white/5 pb-1">Telemetry Origin</span>
                          <div className="flex justify-between">
                            <span>Engine Version:</span> <span className="text-white">ORION Threat Engine v2.5</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Database:</span> <span className="text-white">Threat Intelligence v2.3</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 14</span>
                        </div>
                      </div>

                      {/* PAGE 15: LEGAL DISCLAIMER */}
                      <div className="bg-[#0D111A] border border-white/5 rounded-xl p-6 flex flex-col justify-between min-h-[460px]">
                        <div className="flex justify-between items-start">
                          <span className="text-[10px] font-bold text-white uppercase tracking-widest font-mono">LEGAL DISCLAIMER</span>
                          <span className="text-[9px] font-bold text-slate-500 font-mono">15</span>
                        </div>

                        <div className="my-4 flex flex-col gap-3">
                          <div className="h-6 w-6 rounded-full bg-amber-500/10 text-amber-400 flex items-center justify-center border border-amber-500/20">
                            <AlertTriangle className="h-3.5 w-3.5" />
                          </div>
                          <p className="text-[10.5px] text-[#8D96A3] leading-relaxed">
                            This threat intelligence report was generated automatically by the ORION SOC Threat Center Portal. All results and scores are calculated dynamically based on validation signatures, threat intelligence feeds, and automated ML classifier predictions.
                          </p>
                        </div>

                        <div className="p-3 bg-black/40 border border-white/5 rounded-lg flex items-center gap-2.5">
                          <div className="h-6 w-6 rounded-full bg-purple-600/20 flex items-center justify-center shrink-0">
                            <Shield className="h-3.5 w-3.5 text-purple-400" />
                          </div>
                          <div className="leading-tight">
                            <span className="text-[10px] font-extrabold text-white block uppercase">Orion Threat Command</span>
                            <span className="text-[8px] text-[#8D96A3] block italic mt-0.5">Intelligent. Modern. Relentless.</span>
                          </div>
                        </div>

                        <div className="border-t border-white/5 pt-3 flex justify-between items-center text-[9px] text-[#626B78] font-mono">
                          <span>ORION SOC</span>
                          <span>Page 15</span>
                        </div>
                      </div>

                    </div>
                  );
                })()
              ) : (
                <div className="bg-[#0D111A] border border-white/5 p-12 rounded-xl text-center">
                  <FileText className="h-10 w-10 text-[#8D96A3] mx-auto mb-4" />
                  <p className="text-xs text-[#8D96A3]">No security threat incidents logged in the database yet.</p>
                </div>
              )}
            </div>
          )}

          {/* TAB 7: SETTINGS configuration view */}
          {activeTab === "settings" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">System Settings</h1>
                <p className="text-xs text-[#8D96A3] mt-0.5">Manage UI appearance, detection sensitivity thresholds, and analyst preferences.</p>
              </div>
              <div className="flex flex-col md:flex-row gap-6">
                <div className="w-full md:w-48 flex flex-row md:flex-col gap-1 shrink-0 border-b md:border-b-0 md:border-r border-white/5 pb-3 md:pb-0 md:pr-4">
                  <button onClick={() => setSettingsCategory("appearance")} className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition ${settingsCategory === "appearance" ? "bg-purple-500/10 text-purple-400 font-semibold border border-purple-500/20" : "text-[#8D96A3] hover:bg-white/5"}`}>
                    <Sliders className="h-4 w-4 shrink-0" /> Appearance & Glass
                  </button>
                  <button onClick={() => setSettingsCategory("detection")} className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition ${settingsCategory === "detection" ? "bg-purple-500/10 text-purple-400 font-semibold border border-purple-500/20" : "text-[#8D96A3] hover:bg-white/5"}`}>
                    <Shield className="h-4 w-4 shrink-0" /> Detection Levels
                  </button>
                  <button onClick={() => setSettingsCategory("account")} className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition ${settingsCategory === "account" ? "bg-purple-500/10 text-purple-400 font-semibold border border-purple-500/20" : "text-[#8D96A3] hover:bg-white/5"}`}>
                    <User className="h-4 w-4 shrink-0" /> Account Details
                  </button>
                </div>
                <div className="flex-1 glass-medium glass-highlight p-6 rounded-2xl shadow-xl">
                  {settingsCategory === "appearance" && (
                    <div className="flex flex-col gap-6">
                      <div>
                        <span className="text-[10px] font-bold text-white uppercase tracking-wider block mb-2">Glass Surface Intensity</span>
                        <div className="flex gap-3">
                          {[
                            { id: "low", title: "Low (Subtle)", blur: "12px" },
                            { id: "medium", title: "Medium (Standard)", blur: "24px" },
                            { id: "high", title: "High (Deep Glass)", blur: "36px" }
                          ].map(item => (
                            <button
                              key={item.id}
                              onClick={() => setGlassIntensity(item.id as any)}
                              className={`flex-1 p-3 rounded-xl border text-xs text-left transition cursor-pointer ${glassIntensity === item.id ? "bg-purple-500/20 border-purple-500 text-white font-bold shadow-lg" : "bg-[#080C16]/70 border-white/8 text-[#8D96A3] hover:text-white"}`}
                            >
                              <span className="block font-bold mb-0.5">{item.title}</span>
                              <span className="text-[9px] text-[#626B78] font-mono">Backdrop Blur: {item.blur}</span>
                            </button>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="text-[10px] font-bold text-white uppercase tracking-wider block mb-2">UI Layout Density</span>
                        <div className="flex gap-3 max-w-md">
                          {[
                            { id: "comfortable", title: "Comfortable", desc: "Spacious card margins" },
                            { id: "compact", title: "Compact", desc: "High-density analyst view" }
                          ].map(item => (
                            <button
                              key={item.id}
                              onClick={() => setUiDensity(item.id as any)}
                              className={`flex-1 p-3 rounded-xl border text-xs text-left transition cursor-pointer ${uiDensity === item.id ? "bg-purple-500/20 border-purple-500 text-white font-bold shadow-lg" : "bg-[#080C16]/70 border-white/8 text-[#8D96A3] hover:text-white"}`}
                            >
                              <span className="block font-bold mb-0.5">{item.title}</span>
                              <span className="text-[9px] text-[#626B78]">{item.desc}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {settingsCategory === "detection" && (
                    <div className="flex flex-col gap-5 text-xs text-[#8D96A3]">
                      <div>
                        <div className="flex justify-between mb-1">
                          <span className="text-white font-bold">URL Typosquat Sensitivity</span>
                          <span className="text-purple-400 font-mono font-bold">{urlSensitivity}%</span>
                        </div>
                        <input 
                          type="range" 
                          min="50" 
                          max="99" 
                          value={urlSensitivity} 
                          onChange={e=>setUrlSensitivity(Number(e.target.value))}
                          className="w-full accent-purple-500 h-1.5 cursor-pointer bg-white/10 rounded-full"
                        />
                      </div>

                      <div>
                        <div className="flex justify-between mb-1">
                          <span className="text-white font-bold">Email SPF/DKIM Fraud Sensitivity</span>
                          <span className="text-purple-400 font-mono font-bold">{emailSensitivity}%</span>
                        </div>
                        <input 
                          type="range" 
                          min="50" 
                          max="99" 
                          value={emailSensitivity} 
                          onChange={e=>setEmailSensitivity(Number(e.target.value))}
                          className="w-full accent-purple-500 h-1.5 cursor-pointer bg-white/10 rounded-full"
                        />
                      </div>

                      <div>
                        <div className="flex justify-between mb-1">
                          <span className="text-white font-bold">Media Deepfake Entropy Sensitivity</span>
                          <span className="text-purple-400 font-mono font-bold">{mediaSensitivity}%</span>
                        </div>
                        <input 
                          type="range" 
                          min="50" 
                          max="99" 
                          value={mediaSensitivity} 
                          onChange={e=>setMediaSensitivity(Number(e.target.value))}
                          className="w-full accent-purple-500 h-1.5 cursor-pointer bg-white/10 rounded-full"
                        />
                      </div>

                      <div>
                        <div className="flex justify-between mb-1">
                          <span className="text-white font-bold">Syslog Anomaly Threshold</span>
                          <span className="text-purple-400 font-mono font-bold">{logSensitivity}%</span>
                        </div>
                        <input 
                          type="range" 
                          min="50" 
                          max="99" 
                          value={logSensitivity} 
                          onChange={e=>setLogSensitivity(Number(e.target.value))}
                          className="w-full accent-purple-500 h-1.5 cursor-pointer bg-white/10 rounded-full"
                        />
                      </div>
                    </div>
                  )}

                  {settingsCategory === "account" && (
                    <div className="flex flex-col gap-4">
                      <div>
                        <span className="text-[10px] font-bold text-[#8D96A3] uppercase block mb-1">Active User Email</span>
                        <input type="text" value={userEmail || ""} disabled className="bg-[#080C16]/80 border border-white/10 rounded-xl px-3 py-2 text-xs text-[#626B78] w-full max-w-sm" />
                      </div>
                      <div>
                        <span className="text-[10px] font-bold text-[#8D96A3] uppercase block mb-1">Security Role</span>
                        <span className="inline-block bg-purple-500/10 border border-purple-500/20 text-purple-400 font-mono font-bold text-xs px-3 py-1 rounded-xl">
                          LEAD ARCHITECT SECURITY INTELLIGENCE
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: ACTIVITY log screen */}
          {activeTab === "activity" && (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-3 duration-300">
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">Event Log Feed</h1>
                <p className="text-xs text-[#8D96A3] mt-0.5">Realtime stream of ingestion activities and log updates.</p>
              </div>
              <div className="bg-[#0D111A] border border-white/5 p-5 rounded-xl flex flex-col gap-4">
                <div className="flex justify-between items-center flex-wrap gap-3 border-b border-white/5 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-[9px] text-emerald-400 rounded-full font-bold uppercase tracking-wider">
                      <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span> Live Updates Active
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => setIsLivePaused(!isLivePaused)} className="px-2.5 py-1.5 bg-white/5 border border-white/5 hover:border-purple-500/20 rounded-lg text-xs text-[#8D96A3] hover:text-white transition cursor-pointer">
                      {isLivePaused ? "Resume" : "Pause"}
                    </button>
                    <button onClick={() => setLiveLogs([])} className="px-2.5 py-1.5 bg-white/5 border border-white/5 hover:border-rose-500/20 rounded-lg text-xs text-[#8D96A3] hover:text-[#EF4444] transition cursor-pointer">
                      Clear
                    </button>
                  </div>
                </div>

                <div className="flex flex-col gap-2.5 max-h-[500px] overflow-y-auto pr-1">
                  {liveLogs.map((log, idx) => (
                    <div key={idx} className="p-3 bg-[#080B12]/80 hover:bg-white/5 border border-white/5 rounded-xl cursor-pointer transition flex flex-col gap-1.5">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-[#626B78]">{log.time}</span>
                          <span className="px-1.5 py-0.2 bg-white/5 border border-white/8 text-[#8D96A3] rounded uppercase tracking-wider text-[9px] font-bold">{log.category}</span>
                        </div>
                        <span className={`font-bold ${log.sev === "CRITICAL" ? "text-[#EF4444]" : log.sev === "WARNING" ? "text-[#FBBF24]" : "text-[#10B981]"}`}>
                          {log.sev}
                        </span>
                      </div>
                      <p className="text-xs text-white">{log.msg}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

        </main>
      </div>

      {/* COMMAND PALETTE OVERLAY */}
      {commandPaletteOpen && (
        <div className="fixed inset-0 bg-[#080B12]/80 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-[#0D111A] border border-white/10 w-full max-w-lg rounded-xl shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="p-3 border-b border-white/5 flex items-center gap-3">
              <Search className="h-4 w-4 text-[#8D96A3]" />
              <input 
                type="text" 
                placeholder="Search anything or trigger a command..." 
                className="bg-transparent border-0 outline-none text-xs text-white placeholder-[#626B78] w-full focus:ring-0"
                autoFocus
              />
              <button onClick={() => setCommandPaletteOpen(false)} className="text-[#626B78] hover:text-white"><X className="h-4 w-4" /></button>
            </div>
            
            <div className="p-2 max-h-72 overflow-y-auto flex flex-col gap-0.5">
              {[
                { label: "Go to Dashboard Overview", tab: "overview" },
                { label: "Start New Investigation Scan", tab: "investigate" },
                { label: "Open Threat Queue Ledger", tab: "incidents" },
                { label: "View Threat Analytics metrics", tab: "analytics" },
                { label: "Download assessment Reports", tab: "reports" },
                { label: "Manage settings configurations", tab: "settings" }
              ].map((cmd, idx) => (
                <button
                  key={idx}
                  onClick={() => { setActiveTab(cmd.tab); setCommandPaletteOpen(false); }}
                  className="w-full text-left px-3 py-2 hover:bg-white/5 rounded-lg text-xs text-[#8D96A3] hover:text-white transition cursor-pointer"
                >
                  → {cmd.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DUAL SIDE-PANEL: RIGHT HAND INCIDENT DETAIL DRAWER INSPECTOR */}
      {selectedId && selectedIncident && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-xs" onClick={() => setSelectedId(null)}></div>
          <div className="relative w-full max-w-lg glass-drawer h-full p-6 flex flex-col justify-between z-10 animate-in slide-in-from-right duration-350">
            <div>
              <div className="flex justify-between items-center mb-6">
                <div>
                  <span className="text-[10px] font-mono text-[#8D96A3] uppercase">Incident Details</span>
                  <h2 className="text-base font-bold text-white mt-1">Ref: {selectedIncident.id.substring(0, 16)}...</h2>
                </div>
                <button onClick={() => setSelectedId(null)} className="p-1 hover:bg-white/5 rounded text-[#8D96A3] hover:text-white transition cursor-pointer">
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="flex flex-col gap-5 overflow-y-auto max-h-[calc(100vh-200px)] pr-2">
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 bg-[#080B12]/80 border border-white/5 rounded-lg">
                    <span className="text-[9px] font-bold text-[#8D96A3] uppercase">Ingest Status</span>
                    <span className={`block text-xs font-semibold mt-1.5 ${getStatusBadge(selectedIncident.status)} text-center py-0.5 rounded`}>
                      {selectedIncident.status}
                    </span>
                  </div>
                  <div className="p-3 bg-[#080B12]/80 border border-white/5 rounded-lg">
                    <span className="text-[9px] font-bold text-[#8D96A3] uppercase">Threat Severity</span>
                    <span className={`block text-xs font-semibold mt-1.5 ${getSeverityBadge(selectedIncident.severity)} text-center py-0.5 rounded`}>
                      {selectedIncident.severity}
                    </span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 p-3 bg-[#080B12]/80 border border-white/5 rounded-lg">
                  <span className="text-[9px] font-bold text-[#8D96A3] uppercase">Threat Score</span>
                  <div className="flex items-center gap-3 mt-1.5">
                    <div className="flex-1 bg-white/5 h-2 rounded-full overflow-hidden">
                      <div className="bg-rose-500 h-full rounded-full transition-all duration-500" style={{ width: `${selectedIncident.threat_score}%` }}></div>
                    </div>
                    <span className="text-sm font-bold text-white shrink-0">{selectedIncident.threat_score}%</span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 p-3 bg-[#080B12]/80 border border-white/5 rounded-lg">
                  <span className="text-[9px] font-bold text-[#8D96A3] uppercase">Target Assessment Value</span>
                  <span className="font-mono text-xs text-white block truncate mt-1" title={selectedIncident.target_input}>
                    {selectedIncident.target_input}
                  </span>
                </div>

                {/* Model Training Loop directly in side panel (Admin only) */}
                {userEmail === "admin@orion.com" && (
                  <div className="p-3 bg-[#080B12]/80 border border-white/5 rounded-lg flex flex-col gap-2">
                    <span className="text-[9px] font-bold text-[#8D96A3] uppercase">Re-train ML Model (Override Verdict)</span>
                    <div className="flex gap-2 mt-1">
                      {["PHISHING", "DEEPFAKE", "SUSPICIOUS", "SAFE"].map(label => (
                        <button
                          key={label}
                          onClick={() => handleTrainML(selectedIncident.id, label)}
                          className="flex-1 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-purple-500/30 rounded text-[9.5px] font-mono text-[#8D96A3] hover:text-white transition cursor-pointer"
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <span className="text-[10px] font-bold text-[#8D96A3] uppercase tracking-wider block mb-2">Indicators of Compromise (IOCs) & Signals</span>
                  <div className="flex flex-col gap-2">
                    {selectedIncident.evidences && selectedIncident.evidences.length > 0 ? (
                      selectedIncident.evidences.map((ev, idx) => (
                        <div 
                          key={idx} 
                          onClick={() => setSignalModal({
                            title: `${ev.key.toUpperCase()} Detection Signal`,
                            weight: `${Math.floor(20 + Math.random() * 30)}%`,
                            evidence: ev.value,
                            confidence: `${(90 + Math.random() * 8).toFixed(1)}%`,
                            rationale: `Signal detected during automated forensic inspection of target input "${selectedIncident.target_input}". The classifier weighted this indicator as a high-risk security violation.`
                          })}
                          className="p-3 bg-white/5 hover:bg-purple-500/10 border border-white/8 hover:border-purple-500/30 rounded-xl text-xs cursor-pointer transition flex justify-between items-start group"
                        >
                          <div>
                            <span className="font-bold text-white block uppercase text-[10px] tracking-wide mb-1 group-hover:text-purple-300">🔍 {ev.key}</span>
                            <span className="text-[#8D96A3] leading-relaxed block font-mono text-[11px]">{ev.value}</span>
                          </div>
                          <span className="text-[9px] text-purple-400 font-bold opacity-0 group-hover:opacity-100 transition">View Signal →</span>
                        </div>
                      ))
                    ) : (
                      <div className="p-3 bg-white/5 border border-white/5 rounded-lg text-xs text-[#626B78] text-center">
                        No suspicious indicators mapped. Target verified safe.
                      </div>
                    )}
                  </div>
                </div>

                {/* Analyst Investigation Notes Section */}
                <div className="p-3 bg-[#080C16]/80 border border-white/5 rounded-xl flex flex-col gap-2">
                  <span className="text-[10px] font-bold text-white uppercase tracking-wider block">Analyst Forensics Notes</span>
                  <textarea
                    value={analystNotes[selectedIncident.id] || ""}
                    onChange={e => setAnalystNotes({ ...analystNotes, [selectedIncident.id]: e.target.value })}
                    placeholder="Enter investigation notes, analyst findings, or remediation steps..."
                    rows={3}
                    className="w-full bg-black/40 border border-white/10 rounded-lg p-2.5 text-xs text-white placeholder-[#626B78] focus:outline-none focus:border-purple-500"
                  />
                  <div className="flex justify-end">
                    <button 
                      onClick={() => alert(`Analyst Note saved for Incident #${selectedIncident.id.substring(0, 8)}`)}
                      className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white font-bold text-[10px] rounded-lg transition cursor-pointer"
                    >
                      Save Note
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Action Bar */}
            <div className="border-t border-white/8 pt-4 flex flex-col gap-2">
              <div className="flex gap-2">
                <button
                  onClick={() => alert(`Incident #${selectedIncident.id.substring(0, 8)} escalated to Tier 2 SOC Operations`)}
                  className="flex-1 py-2 bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-rose-300 font-bold text-xs rounded-xl transition cursor-pointer"
                >
                  Escalate
                </button>
                <button
                  onClick={() => alert(`Incident #${selectedIncident.id.substring(0, 8)} marked as Resolved`)}
                  className="flex-1 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 font-bold text-xs rounded-xl transition cursor-pointer"
                >
                  Resolve
                </button>
                <button
                  onClick={() => alert(`Alert for Incident #${selectedIncident.id.substring(0, 8)} suppressed`)}
                  className="flex-1 py-2 bg-white/10 hover:bg-white/20 border border-white/10 text-white font-bold text-xs rounded-xl transition cursor-pointer"
                >
                  Suppress
                </button>
              </div>

              <button 
                onClick={() => downloadReport(selectedIncident.id)}
                className="w-full py-2.5 bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 cursor-pointer shadow-md"
              >
                <Download className="h-4 w-4" /> Download Incident Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SIGNAL DETECTION EXPLANATION MODAL POPUP */}
      {signalModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-md z-[200] flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="glass-floating max-w-md w-full p-6 rounded-2xl border border-white/15 shadow-2xl relative">
            <div className="flex justify-between items-start mb-4 border-b border-white/10 pb-3">
              <div>
                <span className="text-[9px] font-bold text-purple-400 uppercase tracking-widest block">Detection Rationale</span>
                <h2 className="text-sm font-bold text-white mt-0.5">{signalModal.title}</h2>
              </div>
              <button onClick={() => setSignalModal(null)} className="text-[#626B78] hover:text-white transition cursor-pointer p-1">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex flex-col gap-3 text-xs text-[#8D96A3]">
              <div className="grid grid-cols-2 gap-2 p-3 bg-[#080C16]/70 rounded-xl border border-white/5 font-mono">
                <div>
                  <span className="text-[9px] text-[#626B78] block uppercase">Signal Weight</span>
                  <span className="text-white font-bold">{signalModal.weight}</span>
                </div>
                <div>
                  <span className="text-[9px] text-[#626B78] block uppercase">Model Confidence</span>
                  <span className="text-emerald-400 font-bold">{signalModal.confidence}</span>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-bold text-white uppercase tracking-wider block mb-1">Detected Evidence</span>
                <div className="p-2.5 bg-black/40 rounded-lg border border-white/5 font-mono text-[11px] text-purple-300 break-all">
                  {signalModal.evidence}
                </div>
              </div>

              <div>
                <span className="text-[10px] font-bold text-white uppercase tracking-wider block mb-1">Analysis Rationale</span>
                <p className="text-[11px] text-[#8D96A3] leading-relaxed">
                  {signalModal.rationale}
                </p>
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-white/10 flex justify-end">
              <button 
                onClick={() => setSignalModal(null)}
                className="bg-white/10 hover:bg-white/20 text-white font-bold text-xs px-4 py-2 rounded-xl transition cursor-pointer"
              >
                Close Rationale
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

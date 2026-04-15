/**
 * NIDSDashboard.jsx
 * ─────────────────
 * A production-ready NIDS dashboard with:
 *  - Live alert feed (WebSocket-driven, real backend in production)
 *  - Severity counters
 *  - Traffic volume sparkline (Recharts)
 *  - Top attacking IPs bar chart
 *  - Rule hit frequency table
 *  - Pause / clear / filter controls
 *
 * Production mode: Connects to real WebSocket and REST API
 * Demo mode: Uses mock data generator (when API unavailable)
 */

import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from "recharts";

// ─────────────────────────────────────────────────────────────
// Constants & helpers
// ─────────────────────────────────────────────────────────────

const API_BASE = "http://localhost:8000/api/v1";
const WS_URL = "ws://localhost:8000/ws/alerts";

const SEV_ORDER = ["critical", "high", "medium", "low"];

const SEV_STYLE = {
  critical: { bg: "#3a0a0a", border: "#e53e3e", text: "#fc8181", dot: "#e53e3e" },
  high: { bg: "#2d1600", border: "#dd6b20", text: "#f6ad55", dot: "#dd6b20" },
  medium: { bg: "#1a2a00", border: "#68d391", text: "#9ae6b4", dot: "#68d391" },
  low: { bg: "#0a1a2a", border: "#4299e1", text: "#90cdf4", dot: "#4299e1" },
};

const RULE_LABELS = {
  "RATE-001": "Port Scan",
  "RATE-002": "Brute Force",
  "RATE-003": "SYN Flood",
  "RATE-004": "ICMP Flood",
  "RATE-005": "Host Sweep",
  "RATE-006": "DNS Flood",
  "RATE-007": "Exfiltration",
  "WEB-001": "SQL Injection",
  "WEB-003": "XSS",
  "WEB-004": "Path Traversal",
  "WEB-005": "Cmd Injection",
  "C2-001": "DNS Tunnel",
  "C2-002": "C2 Beacon",
  "MAL-001": "Mimikatz",
  "MAL-003": "Webshell",
  "CVE-2021-44228": "Log4Shell",
};

function fmt(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-US", { hour12: false });
}

function randomIp() {
  const pools = [
    ["185", "220", "101"], ["91", "108", "4"], ["198", "199", "119"],
    ["45", "142", "212"], ["176", "10", "99"], ["103", "21", "244"]
  ];
  const p = pools[Math.floor(Math.random() * pools.length)];
  return `${p[0]}.${p[1]}.${p[2]}.${Math.floor(Math.random() * 254 + 1)}`;
}

const RULE_IDS = Object.keys(RULE_LABELS);

function mockAlert() {
  const rule = RULE_IDS[Math.floor(Math.random() * RULE_IDS.length)];
  const sevs = ["critical", "high", "high", "medium", "medium", "medium", "low"];
  const sev = sevs[Math.floor(Math.random() * sevs.length)];
  return {
    id: Math.random().toString(36).slice(2),
    rule_id: rule,
    severity: sev,
    description: `${RULE_LABELS[rule]} detected from source`,
    src_ip: randomIp(),
    dst_ip: `10.0.0.${Math.floor(Math.random() * 30 + 1)}`,
    dst_port: [22, 80, 443, 3306, 3389][Math.floor(Math.random() * 5)],
    count: Math.floor(Math.random() * 400 + 10),
    window_sec: [5, 10, 30][Math.floor(Math.random() * 3)],
    timestamp: Date.now() / 1000,
  };
}

// ─────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────

function StatCard({ label, value, color }) {
  return (
    <div style={{
      flex: 1, minWidth: 100,
      background: "#111",
      border: `1px solid ${color}44`,
      borderTop: `2px solid ${color}`,
      borderRadius: 6,
      padding: "14px 18px",
    }}>
      <div style={{ fontSize: 11, letterSpacing: 2, color: "#555", textTransform: "uppercase", marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontSize: 32, fontFamily: "'JetBrains Mono', monospace", color, fontWeight: 700, lineHeight: 1 }}>
        {value}
      </div>
    </div>
  );
}

function SeverityBadge({ sev }) {
  const s = SEV_STYLE[sev] || SEV_STYLE.low;
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1.5,
      padding: "2px 8px", borderRadius: 3,
      background: s.bg, border: `1px solid ${s.border}`,
      color: s.text, textTransform: "uppercase",
    }}>
      {sev}
    </span>
  );
}

function AlertRow({ alert }) {
  const s = SEV_STYLE[alert.severity] || SEV_STYLE.low;
  // Get rule IDs - handle both rule_id (string) and rule_ids (array)
  const ruleIds = alert.rule_ids || (alert.rule_id ? [alert.rule_id] : []);

  // Create formatted rule display with names
  const getRuleDisplay = (ruleId) => {
    const name = RULE_LABELS[ruleId] || ruleId;
    return `${ruleId}`;
  };

  const ruleIdDisplay = ruleIds.length > 0
    ? ruleIds.map(r => getRuleDisplay(r)).join(" | ")
    : "N/A";

  // Get title or description
  const displayTitle = alert.title || alert.description || "Unknown Alert";

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "70px 80px 120px 100px 90px 1fr",
      gap: 8,
      padding: "8px 12px",
      borderBottom: "1px solid #1e1e1e",
      borderLeft: `3px solid ${s.dot}`,
      fontSize: 11,
      fontFamily: "'JetBrains Mono', monospace",
      background: "#0d0d0d",
      transition: "background 0.15s",
      alignItems: "center",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "#161616"}
      onMouseLeave={e => e.currentTarget.style.background = "#0d0d0d"}
    >
      <span style={{ color: "#444", fontSize: 10 }}>{fmt(alert.timestamp)}</span>
      <SeverityBadge sev={alert.severity} />
      <span style={{ color: "#f6ad55", fontSize: 9, fontWeight: 600 }}>{ruleIdDisplay}</span>
      <span style={{ color: "#e0e0e0", fontSize: 10 }}>{alert.src_ip}</span>
      <span style={{ color: "#666", fontSize: 10 }}>{alert.dst_ip}:{alert.dst_port || "—"}</span>
      <span style={{ color: "#aaa", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {displayTitle}
      </span>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#161616", border: "1px solid #333", padding: "8px 12px", borderRadius: 4, fontSize: 12, fontFamily: "monospace" }}>
      <div style={{ color: "#666", marginBottom: 4 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────
// Main dashboard
// ─────────────────────────────────────────────────────────────

export default function NIDSDashboard({ onLogout }) {
  const [alerts, setAlerts] = useState([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");  // severity filter
  const [traffic, setTraffic] = useState(
    Array.from({ length: 30 }, (_, i) => ({
      t: fmt((Date.now() / 1000) - (29 - i) * 2),
      pkts: Math.floor(Math.random() * 200 + 50),
      alerts: 0,
    }))
  );
  const [connected, setConnected] = useState(false);
  const [useMock, setUseMock] = useState(false);
  const [totalPackets, setTotalPackets] = useState(0);

  const feedRef = useRef(null);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  // Fetch real-time traffic metrics from API
  useEffect(() => {
    if (pausedRef.current) return;

    async function fetchTraffic() {
      try {
        const resp = await fetch(`${API_BASE}/metrics`);
        if (resp.ok) {
          const data = await resp.json();
          setTotalPackets(data.total_packets || 0);
          setTraffic(prev => {
            const next = [...prev.slice(1), {
              t: fmt(Date.now() / 1000),
              pkts: data.packets_per_sec || 0,
              alerts: 0,
            }];
            return next;
          });
        }
      } catch (e) {
        // Fallback to simulated if API unavailable
      }
    }

    const interval = setInterval(fetchTraffic, 2000);
    fetchTraffic(); // Initial fetch

    return () => clearInterval(interval);
  }, []);

  // Fetch initial data from API
  useEffect(() => {
    async function fetchData() {
      try {
        // Try to fetch alerts from API
        const resp = await fetch(`${API_BASE}/alerts?limit=50`);
        if (resp.ok) {
          const data = await resp.json();
          setAlerts(data.alerts || []);
          setConnected(true);
          setUseMock(false);

          // Also fetch stats for packet info
          try {
            const statsResp = await fetch(`${API_BASE}/stats`);
            if (statsResp.ok) {
              const stats = await statsResp.json();
              setSimulatedTraffic(stats.total_alerts * 100); // Approximate
            }
          } catch { }
        } else {
          throw new Error("API unavailable");
        }
      } catch (e) {
        console.log("API not available, using mock data:", e.message);
        setUseMock(true);
        setConnected(false);
      }
    }
    fetchData();
  }, []);

  // Setup WebSocket connection
  useEffect(() => {
    if (useMock) return; // Skip WS in mock mode

    let ws;
    let reconnectTimer;

    function connect() {
      try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
          console.log("WebSocket connected");
          setConnected(true);
        };

        ws.onmessage = (e) => {
          console.log("WebSocket message received:", e.data);
          if (pausedRef.current) return;
          try {
            const alert = JSON.parse(e.data);
            console.log("Parsed alert:", alert);
            setAlerts(prev => [alert, ...prev].slice(0, 200));
            setTraffic(prev => {
              const next = [...prev.slice(1), {
                t: fmt(alert.timestamp),
                pkts: Math.floor(Math.random() * 300 + 100),
                alerts: (prev[prev.length - 1].alerts || 0) + 1,
              }];
              return next;
            });
            setSimulatedTraffic(prev => prev + 50);
          } catch (err) {
            console.error("WS parse error:", err);
          }
        };

        ws.onclose = () => {
          console.log("WebSocket disconnected");
          setConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        };

        ws.onerror = (e) => {
          console.error("WebSocket error:", e);
        };
      } catch (e) {
        console.error("WS connect error:", e);
      }
    }

    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [useMock]);

  const addAlert = useCallback((alert) => {
    if (pausedRef.current) return;
    setAlerts(prev => [alert, ...prev].slice(0, 200));
    setTraffic(prev => {
      const next = [...prev.slice(1), {
        t: fmt(alert.timestamp),
        pkts: Math.floor(Math.random() * 300 + 100),
        alerts: (prev[prev.length - 1].alerts || 0) + 1,
      }];
      return next;
    });
  }, []);

  // Mock feed for demo mode
  useEffect(() => {
    if (!useMock) return;

    const id = setInterval(() => {
      if (!pausedRef.current) addAlert(mockAlert());
    }, 1200);
    return () => clearInterval(id);
  }, [useMock, addAlert]);

  // ── derived stats ──
  const counts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = alerts.filter(a => a.severity && a.severity.toLowerCase() === s).length;
    return acc;
  }, {});

  const topIPs = Object.entries(
    alerts.reduce((acc, a) => {
      const ip = a.src_ip || "unknown";
      acc[ip] = (acc[ip] || 0) + 1;
      return acc;
    }, {})
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => ({ ip: ip.split(".").slice(0, 3).join(".") + ".*", count }));

  const ruleHits = Object.entries(
    alerts.reduce((acc, a) => {
      const rules = a.rule_ids || [a.rule_id];
      rules.forEach(r => { acc[r] = (acc[r] || 0) + 1; });
      return acc;
    }, {})
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const displayed = filter === "all"
    ? alerts
    : alerts.filter(a => a.severity && a.severity.toLowerCase() === filter.toLowerCase());

  // ── render ──
  return (
    <div style={{
      background: "#080808",

      color: "#d0d0d0",
      minHeight: "100vh",
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      padding: "0 0 40px",
    }}>

      {/* ── Header ── */}
      <div style={{
        background: "#0d0d0d",
        borderBottom: "1px solid #1a1a1a",
        padding: "14px 28px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 10, height: 10, borderRadius: "50%",
            background: connected ? "#48bb78" : (useMock ? "#f6ad55" : "#555"),
            boxShadow: connected ? "0 0 8px #48bb78" : "none",
            animation: connected ? "pulse 2s infinite" : "none",
          }} />
          <span style={{ fontSize: 14, letterSpacing: 3, color: "#e0e0e0", textTransform: "uppercase" }}>
            NIDS · Network Intrusion Detection
          </span>
          <span style={{ fontSize: 11, color: "#666", marginLeft: 8, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: connected ? "#48bb78" : (useMock ? "#f6ad55" : "#555"),
              animation: "pulse 2s infinite"
            }} />
            {connected ? "Capturing" : (useMock ? "Demo" : "Offline")}
          </span>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={() => setPaused(p => !p)}
            style={{
              background: "transparent",
              border: `1px solid ${paused ? "#48bb78" : "#555"}`,
              color: paused ? "#48bb78" : "#888",
              padding: "5px 14px",
              borderRadius: 4,
              fontSize: 11,
              letterSpacing: 1.5,
              cursor: "pointer",
              textTransform: "uppercase",
            }}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
          <button
            onClick={() => setAlerts([])}
            style={{
              background: "transparent",
              border: "1px solid #333",
              color: "#666",
              padding: "5px 14px",
              borderRadius: 4,
              fontSize: 11,
              letterSpacing: 1.5,
              cursor: "pointer",
              textTransform: "uppercase",
            }}
          >
            ✕ Clear
          </button>
          <button
            onClick={onLogout}
            style={{
              background: "transparent",
              border: "1px solid #333",
              color: "#666",
              padding: "5px 14px",
              borderRadius: 4,
              fontSize: 11,
              letterSpacing: 1.5,
              cursor: "pointer",
              textTransform: "uppercase",
            }}
          >
            ⏻ Logout
          </button>
        </div>
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
      `}</style>

      <div style={{ padding: "20px 28px", display: "flex", flexDirection: "column", gap: 20 }}>

        {/* ── Stat cards ── */}
        <div style={{ display: "flex", gap: 12 }}>
          <StatCard label="Total alerts" value={alerts.length} color="#a0a0a0" />
          <StatCard label="Packets" value={totalPackets} color="#4299e1" />
          <StatCard label="Critical" value={counts.critical || 0} color="#e53e3e" />
          <StatCard label="High" value={counts.high || 0} color="#dd6b20" />
          <StatCard label="Medium" value={counts.medium || 0} color="#68d391" />
          <StatCard label="Low" value={counts.low || 0} color="#4299e1" />
        </div>

        {/* ── Charts row ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

          {/* Traffic + alerts over time */}
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 6, padding: "16px 20px" }}>
            <div style={{ fontSize: 11, letterSpacing: 2, color: "#444", textTransform: "uppercase", marginBottom: 14 }}>
              Traffic volume
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={traffic} margin={{ top: 0, right: 0, bottom: 0, left: -30 }}>
                <defs>
                  <linearGradient id="gp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4299e1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#4299e1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e53e3e" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#e53e3e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" />
                <XAxis dataKey="t" tick={{ fill: "#444", fontSize: 9 }} tickLine={false} axisLine={false} interval={9} />
                <YAxis tick={{ fill: "#444", fontSize: 9 }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="pkts" name="packets" stroke="#4299e1" fill="url(#gp)" strokeWidth={1.5} dot={false} />
                <Area type="monotone" dataKey="alerts" name="alerts" stroke="#e53e3e" fill="url(#ga)" strokeWidth={1.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Top attacking IPs */}
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 6, padding: "16px 20px" }}>
            <div style={{ fontSize: 11, letterSpacing: 2, color: "#444", textTransform: "uppercase", marginBottom: 14 }}>
              Top attacking IPs
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={topIPs} layout="vertical" margin={{ top: 0, right: 0, bottom: 0, left: 40 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#444", fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="ip" tick={{ fill: "#777", fontSize: 9 }} tickLine={false} axisLine={false} width={70} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="hits" fill="#dd6b20" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Rule hits + alert feed side-by-side ── */}
        <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 16 }}>

          {/* Rule frequency table */}
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 6, padding: "16px 0" }}>
            <div style={{ fontSize: 11, letterSpacing: 2, color: "#444", textTransform: "uppercase", marginBottom: 10, padding: "0 16px" }}>
              Rule hits
            </div>
            {ruleHits.map(([rule_id, count]) => {
              const pct = ruleHits[0] ? Math.round(count / ruleHits[0][1] * 100) : 0;
              return (
                <div key={rule_id} style={{ padding: "7px 16px", borderBottom: "1px solid #141414" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: "#a0a0a0" }}>{RULE_LABELS[rule_id] || rule_id}</span>
                    <span style={{ fontSize: 11, color: "#555" }}>{count}</span>
                  </div>
                  <div style={{ height: 2, background: "#1a1a1a", borderRadius: 2 }}>
                    <div style={{ height: 2, width: `${pct}%`, background: "#e53e3e", borderRadius: 2, opacity: 0.7 }} />
                  </div>
                </div>
              );
            })}
            {ruleHits.length === 0 && (
              <div style={{ padding: "20px 16px", fontSize: 11, color: "#333" }}>No data yet</div>
            )}
          </div>

          {/* Alert feed */}
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 6, overflow: "hidden" }}>
            {/* Feed header + filter */}
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "12px 16px", borderBottom: "1px solid #1a1a1a", gap: 8,
            }}>
              <div style={{ fontSize: 11, letterSpacing: 2, color: "#444", textTransform: "uppercase" }}>
                Alert feed <span style={{ color: "#333", marginLeft: 6 }}>{displayed.length}</span>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                {["all", ...SEV_ORDER].map(s => (
                  <button key={s}
                    onClick={() => setFilter(s)}
                    style={{
                      background: filter === s ? (SEV_STYLE[s]?.bg || "#1a1a1a") : "transparent",
                      border: `1px solid ${filter === s ? (SEV_STYLE[s]?.border || "#555") : "#2a2a2a"}`,
                      color: filter === s ? (SEV_STYLE[s]?.text || "#ccc") : "#444",
                      padding: "3px 10px",
                      borderRadius: 3,
                      fontSize: 10,
                      letterSpacing: 1,
                      cursor: "pointer",
                      textTransform: "uppercase",
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* Column headers */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "70px 80px 120px 100px 90px 1fr",
              gap: 8,
              padding: "6px 12px",
              fontSize: 9,
              color: "#444",
              letterSpacing: 1,
              textTransform: "uppercase",
              borderBottom: "1px solid #161616",
            }}>
              <span>Time</span><span>Severity</span><span>Rule ID</span>
              <span>Source</span><span>Dest</span><span>Alert</span>
            </div>

            {/* Scrollable rows */}
            <div ref={feedRef} style={{ maxHeight: 380, overflowY: "auto" }}>
              {displayed.length === 0 ? (
                <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: "#333" }}>
                  Waiting for alerts…
                </div>
              ) : (
                displayed.map(a => <AlertRow key={a.id} alert={a} />)
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

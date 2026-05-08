"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import {
  api, type AuditJob, type Finding, type JobSummary,
  type AiAnalysis, type Remediation, type ComplianceScores,
} from "@/lib/api";
import { Nav } from "@/components/nav";

type Tab = "overview" | "ai" | "compliance" | "security" | "cost" | "errors";

const SEV_DOT: Record<string, string> = {
  Critical: "sev-dot-critical", High: "sev-dot-high", Medium: "sev-dot-medium", Low: "sev-dot-low",
};
const SEV_TEXT: Record<string, string> = {
  Critical: "sev-critical", High: "sev-high", Medium: "sev-medium", Low: "sev-low",
};
const SEV_CARD_BG: Record<string, string> = {
  Critical: "sev-bg-critical", High: "sev-bg-high", Medium: "sev-bg-medium", Low: "sev-bg-low",
};
const SEV_CARD_BORDER: Record<string, string> = {
  Critical: "sev-border-critical", High: "sev-border-high", Medium: "sev-border-medium", Low: "sev-border-low",
};
const SEV_BAR: Record<string, string> = {
  Critical: "sev-bar-critical", High: "sev-bar-high", Medium: "sev-bar-medium", Low: "sev-bar-low",
};
const RISK_COLOR: Record<string, string> = {
  Critical: "text-red-600 bg-red-50 border-red-200",
  High:     "text-orange-600 bg-orange-50 border-orange-200",
  Medium:   "text-yellow-600 bg-yellow-50 border-yellow-200",
  Low:      "text-green-600 bg-green-50 border-green-200",
  Unknown:  "text-gray-600 bg-gray-50 border-gray-200",
};
const FW_COLOR: Record<string, { bar: string; badge: string }> = {
  CIS:   { bar: "bg-blue-500",    badge: "bg-blue-100 text-blue-700" },
  PCI:   { bar: "bg-purple-500",  badge: "bg-purple-100 text-purple-700" },
  SOC2:  { bar: "bg-indigo-500",  badge: "bg-indigo-100 text-indigo-700" },
  HIPAA: { bar: "bg-pink-500",    badge: "bg-pink-100 text-pink-700" },
  NIST:  { bar: "bg-teal-500",    badge: "bg-teal-100 text-teal-700" },
};

function categorise(findings: Finding[]) {
  const security: Finding[] = [], compliance: Finding[] = [], cost: Finding[] = [], errors: Finding[] = [];
  for (const f of findings) {
    if (f.status === "ERROR" || f.status === "SKIPPED") { errors.push(f); continue; }
    if (f.service?.toLowerCase().includes("cost") || f.finding_type?.toLowerCase().includes("cost")) { cost.push(f); continue; }
    if (Object.keys(f.compliance ?? {}).length > 0) { compliance.push(f); continue; }
    security.push(f);
  }
  return { security, compliance, cost, errors };
}

export default function AuditDetailPage() {
  const router = useRouter();
  const { id } = useParams<{ id: string }>();

  const [job, setJob]                     = useState<AuditJob | null>(null);
  const [summary, setSummary]             = useState<JobSummary | null>(null);
  const [allFindings, setAll]             = useState<Finding[]>([]);
  const [tab, setTab]                     = useState<Tab>("overview");
  const [loading, setLoading]             = useState(true);
  const [sevFilter, setSev]               = useState("");
  const [statusFilter, setStatus]         = useState("");
  // AI state
  const [analysis, setAnalysis]           = useState<AiAnalysis | null>(null);
  const [analysisLoading, setAnaLoading]  = useState(false);
  const [analysisError, setAnaError]      = useState("");
  // Compliance state
  const [compScores, setCompScores]       = useState<ComplianceScores | null>(null);
  const [compLoading, setCompLoading]     = useState(false);
  // Report state
  const [reportLoading, setReportLoading] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    const chunks: Finding[] = [];
    let p = 1;
    while (true) {
      const chunk = await api.getFindings(id, { page: String(p), page_size: "200" });
      chunks.push(...chunk);
      if (chunk.length < 200) break;
      p++;
    }
    setAll(chunks);
    setLoading(false);
  }, [id]);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) router.replace("/auth/login");
    });
    api.getAudit(id).then(setJob);
    api.getSummary(id).then(setSummary);
    loadAll();
    // Try to load cached analysis
    api.getAnalysis(id).then(setAnalysis).catch(() => {});
  }, [id, loadAll, router]);

  async function runAnalysis() {
    setAnaLoading(true); setAnaError("");
    try {
      const result = await api.analyzeJob(id);
      setAnalysis(result);
    } catch (e: unknown) {
      setAnaError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setAnaLoading(false);
    }
  }

  async function loadCompliance() {
    if (compScores) return;
    setCompLoading(true);
    try {
      const scores = await api.getComplianceScores(id);
      setCompScores(scores);
    } catch { /* ignore */ }
    setCompLoading(false);
  }

  useEffect(() => {
    if (tab === "compliance" && !compScores) loadCompliance();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  async function downloadReport() {
    setReportLoading(true);
    try {
      const { report } = await api.generateReport(id);
      // Open in a new tab as markdown
      const blob = new Blob([report], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `audit-report-${id.slice(0,8)}.md`;
      a.click(); URL.revokeObjectURL(url);
    } catch { /* ignore */ }
    setReportLoading(false);
  }

  const { security, compliance, cost, errors } = categorise(allFindings);
  const sevCounts = {
    Critical: summary?.by_severity["Critical"] ?? 0,
    High:     summary?.by_severity["High"]     ?? 0,
    Medium:   summary?.by_severity["Medium"]   ?? 0,
    Low:      summary?.by_severity["Low"]      ?? 0,
  };
  const total = summary?.total ?? 0;
  const riskBar = (["Critical","High","Medium","Low"] as const)
    .map(s => ({ sev: s, count: sevCounts[s], pct: total ? (sevCounts[s]/total)*100 : 0 }))
    .filter(x => x.count > 0);

  const TABS: { id: Tab; label: string; count?: number; icon: string }[] = [
    { id: "overview",    label: "Overview",    icon: "📊" },
    { id: "ai",          label: "AI Analysis", icon: "🤖" },
    { id: "compliance",  label: "Compliance",  icon: "📋" },
    { id: "security",    label: "Security",    icon: "🔐", count: security.length },
    { id: "cost",        label: "Cost",        icon: "💰", count: cost.length },
    { id: "errors",      label: "Errors",      icon: "⚠",  count: errors.length },
  ];

  function tabFindings() {
    let list = tab === "security" ? security : tab === "cost" ? cost : tab === "errors" ? errors : [];
    if (sevFilter)    list = list.filter(f => f.severity === sevFilter);
    if (statusFilter) list = list.filter(f => f.status   === statusFilter);
    return list;
  }
  const displayed = tabFindings();
  const generatedAt = job
    ? new Date(job.created_at).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC"
    : "—";

  return (
    <>
      <Nav />

      {/* Dark header */}
      <div className="bg-[#0f172a] text-white">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center text-2xl shrink-0">🛡️</div>
              <div>
                <h1 className="text-2xl font-bold">AWS Security Audit Report</h1>
                <p className="text-slate-400 text-sm mt-0.5">Multi-account · CIS · PCI-DSS · SOC2 · HIPAA · NIST</p>
              </div>
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={downloadReport} disabled={reportLoading}
                className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
                {reportLoading ? "Generating…" : "📄 Executive Report"}
              </button>
              <button type="button" onClick={() => window.print()}
                className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
                🖨️ Print PDF
              </button>
            </div>
          </div>

          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-6 border-t border-slate-700 pt-6">
            <div>
              <p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">GENERATED</p>
              <p className="text-sm font-bold">{generatedAt}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">ACCOUNTS SCANNED</p>
              <p className="text-xl font-bold">{job?.accounts_audited?.length ?? 0}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">TOTAL FINDINGS</p>
              <p className="text-xl font-bold">{total}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">CRITICAL / HIGH</p>
              <p className={`text-xl font-bold ${(sevCounts.Critical + sevCounts.High) > 0 ? "text-orange-400" : "text-green-400"}`}>
                {sevCounts.Critical} / {sevCounts.High}
              </p>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 flex gap-0 border-t border-slate-700 overflow-x-auto">
          {TABS.map(t => (
            <button key={t.id} type="button" onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${tab === t.id ? "border-orange-400 text-white" : "border-transparent text-slate-400 hover:text-white"}`}>
              <span>{t.icon}</span>
              {t.label}
              {t.count !== undefined && t.count > 0 && (
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${tab === t.id ? "bg-orange-500 text-white" : "bg-slate-600 text-slate-300"}`}>{t.count}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <button type="button" onClick={() => router.back()} className="text-sm text-gray-500 hover:text-gray-800">← Back to Dashboard</button>

        {loading && <p className="text-gray-400 text-sm animate-pulse">Loading findings…</p>}

        {/* ── Overview ── */}
        {tab === "overview" && !loading && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
              <div className="bg-white rounded-2xl border-t-4 border-indigo-500 shadow-sm p-5">
                <span className="text-2xl block mb-2">📋</span>
                <p className="text-3xl font-bold text-gray-800">{total}</p>
                <p className="text-xs text-gray-500 font-semibold tracking-wider mt-1">TOTAL FINDINGS</p>
              </div>
              {(["Critical","High","Medium","Low"] as const).map(s => (
                <div key={s} className={`bg-white rounded-2xl border-t-4 shadow-sm p-5 ${SEV_CARD_BG[s]} ${SEV_CARD_BORDER[s]}`}>
                  <span className={`w-3 h-3 rounded-full block mb-3 ${SEV_DOT[s]}`} />
                  <p className={`text-3xl font-bold ${SEV_TEXT[s]}`}>{sevCounts[s]}</p>
                  <p className="text-xs text-gray-500 font-semibold tracking-wider mt-1">{s.toUpperCase()}</p>
                </div>
              ))}
            </div>

            {total > 0 && (
              <div className="bg-white rounded-2xl border shadow-sm p-6">
                <p className="text-xs font-semibold text-gray-500 tracking-widest mb-3">RISK DISTRIBUTION</p>
                <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
                  {riskBar.map(({ sev, pct }) => (
                    <div key={sev} className={`bar-dynamic ${SEV_BAR[sev]}`}
                      style={{ "--bar-pct": `${pct}%` } as React.CSSProperties} />
                  ))}
                </div>
                <div className="flex gap-4 mt-3 flex-wrap">
                  {riskBar.map(({ sev, count }) => (
                    <span key={sev} className="flex items-center gap-1.5 text-xs text-gray-600">
                      <span className={`w-2.5 h-2.5 rounded-full ${SEV_DOT[sev]}`} />
                      {sev} ({count})
                    </span>
                  ))}
                </div>
              </div>
            )}

            {summary && Object.keys(summary.by_service).length > 0 && (
              <div className="bg-white rounded-2xl border shadow-sm p-6">
                <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">FINDINGS BY SERVICE</p>
                <div className="space-y-2">
                  {Object.entries(summary.by_service).sort(([,a],[,b]) => b-a).map(([svc, cnt]) => (
                    <div key={svc} className="flex items-center gap-3">
                      <span className="text-sm text-gray-700 w-48 truncate">{svc}</span>
                      <div className="flex-1 bg-gray-100 rounded-full h-2">
                        <div className="bg-brand h-2 rounded-full bar-dynamic"
                          style={{ "--bar-pct": `${Math.round((cnt/Math.max(total,1))*100)}%` } as React.CSSProperties} />
                      </div>
                      <span className="text-sm font-semibold text-gray-700 w-6 text-right">{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="grid sm:grid-cols-4 gap-4">
              {([
                { label: "AI Analysis",        icon: "🤖", tid: "ai",         border: "border-l-orange-500", desc: analysis ? analysis.risk_level + " Risk" : "Click to analyse" },
                { label: "Compliance Scores",  icon: "📋", tid: "compliance", border: "border-l-purple-500", desc: "CIS · PCI · SOC2 · HIPAA · NIST" },
                { label: "Security Findings",  icon: "🔐", tid: "security",   border: "border-l-blue-500",   desc: `${security.length} findings` },
                { label: "Cost Findings",      icon: "💰", tid: "cost",       border: "border-l-green-500",  desc: `${cost.length} findings` },
              ] as const).map(({ label, icon, tid, border, desc }) => (
                <button key={label} type="button" onClick={() => setTab(tid as Tab)}
                  className={`bg-white rounded-2xl border shadow-sm p-5 text-left hover:shadow-md transition-shadow border-l-4 ${border}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl">{icon}</span>
                  </div>
                  <p className="text-sm font-semibold text-gray-800">{label}</p>
                  <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
                </button>
              ))}
            </div>

            {job?.accounts_audited && job.accounts_audited.length > 0 && (
              <div className="bg-white rounded-2xl border shadow-sm p-6">
                <p className="text-xs font-semibold text-gray-500 tracking-widest mb-3">ACCOUNTS AUDITED</p>
                <div className="flex flex-wrap gap-2">
                  {job.accounts_audited.map(a => (
                    <span key={a} className="font-mono text-xs bg-gray-100 rounded-lg px-3 py-1.5">{a}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── AI Analysis tab ── */}
        {tab === "ai" && !loading && (
          <div className="space-y-6">
            {!analysis && (
              <div className="bg-white rounded-2xl border shadow-sm p-8 text-center space-y-4">
                <span className="text-5xl block">🤖</span>
                <p className="font-semibold text-gray-800">AI-Powered Findings Analysis</p>
                <p className="text-sm text-gray-500 max-w-md mx-auto">
                  Let the local LLM analyse all {total} findings and provide a risk narrative,
                  top risks, quick wins, and remediation guidance.
                </p>
                {analysisError && <p className="text-sm text-red-600">{analysisError}</p>}
                <button type="button" onClick={runAnalysis} disabled={analysisLoading}
                  className="inline-flex items-center gap-2 bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-white font-semibold px-6 py-2.5 rounded-xl transition-colors">
                  {analysisLoading
                    ? <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Analysing…</>
                    : "▶ Run AI Analysis"}
                </button>
              </div>
            )}

            {analysis && (
              <>
                {/* Risk level banner */}
                <div className={`rounded-2xl border p-5 ${RISK_COLOR[analysis.risk_level] ?? RISK_COLOR.Unknown}`}>
                  <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div>
                      <p className="text-xs font-semibold tracking-widest mb-1">AI RISK ASSESSMENT</p>
                      <p className="text-xl font-bold">{analysis.headline}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-lg font-bold px-4 py-1.5 rounded-xl border-2 ${RISK_COLOR[analysis.risk_level] ?? RISK_COLOR.Unknown}`}>
                        {analysis.risk_level} Risk
                      </span>
                      <button type="button" onClick={runAnalysis} disabled={analysisLoading}
                        className="text-sm text-gray-500 hover:text-gray-800 border px-3 py-1.5 rounded-lg bg-white">
                        {analysisLoading ? "…" : "Refresh"}
                      </button>
                    </div>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed">{analysis.summary}</p>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  {/* Top risks */}
                  <div className="bg-white rounded-2xl border shadow-sm p-6">
                    <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">🚨 TOP RISKS</p>
                    <ul className="space-y-3">
                      {(analysis.top_risks ?? []).map((r, i) => (
                        <li key={i} className="flex gap-3">
                          <span className="w-6 h-6 rounded-full bg-red-100 text-red-600 text-xs font-bold flex items-center justify-center shrink-0">{i+1}</span>
                          <p className="text-sm text-gray-700 leading-relaxed">{r}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                  {/* Quick wins */}
                  <div className="bg-white rounded-2xl border shadow-sm p-6">
                    <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">⚡ QUICK WINS</p>
                    <ul className="space-y-3">
                      {(analysis.quick_wins ?? []).map((w, i) => (
                        <li key={i} className="flex gap-3">
                          <span className="w-6 h-6 rounded-full bg-green-100 text-green-600 text-xs font-bold flex items-center justify-center shrink-0">✓</span>
                          <p className="text-sm text-gray-700 leading-relaxed">{w}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Narrative */}
                <div className="bg-white rounded-2xl border shadow-sm p-6">
                  <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">📝 DETAILED ANALYSIS</p>
                  <div className="prose prose-sm max-w-none text-gray-700 leading-relaxed whitespace-pre-wrap">{analysis.narrative}</div>
                </div>

                {/* Jump to chat */}
                <div className="bg-gradient-to-r from-indigo-50 to-purple-50 rounded-2xl border border-indigo-200 p-6 flex items-center justify-between gap-4">
                  <div>
                    <p className="font-semibold text-indigo-900">Ask the AI anything</p>
                    <p className="text-sm text-indigo-700 mt-0.5">Chat with the AI about these findings — ask about specific risks, remediation steps, or compliance questions.</p>
                  </div>
                  <a href={`/chat?job=${id}`}
                    className="shrink-0 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5 rounded-xl transition-colors text-sm">
                    Open Chat →
                  </a>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Compliance tab ── */}
        {tab === "compliance" && !loading && (
          <div className="space-y-6">
            {compLoading && <p className="text-sm text-gray-400 animate-pulse">Computing compliance scores…</p>}
            {compScores && (
              <>
                <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {Object.entries(compScores).map(([fw, data]) => {
                    const col = FW_COLOR[fw] ?? { bar: "bg-gray-400", badge: "bg-gray-100 text-gray-700" };
                    const score = data.score ?? 0;
                    const scoreColor = score >= 80 ? "text-green-600" : score >= 60 ? "text-yellow-600" : "text-red-600";
                    return (
                      <div key={fw} className="bg-white rounded-2xl border shadow-sm p-5">
                        <div className="flex items-center justify-between mb-3">
                          <span className={`text-xs font-bold px-2 py-0.5 rounded-lg ${col.badge}`}>{fw}</span>
                          <span className={`text-2xl font-extrabold ${scoreColor}`}>{score}%</span>
                        </div>
                        <p className="text-xs text-gray-500 mb-2">{data.framework_name}</p>
                        <div className="h-2 bg-gray-100 rounded-full overflow-hidden mb-3">
                          <div className={`h-2 rounded-full transition-all bar-dynamic ${col.bar}`}
                            style={{ "--bar-pct": `${score}%` } as React.CSSProperties} />
                        </div>
                        <div className="flex gap-3 text-xs text-gray-500">
                          <span className="text-green-600 font-semibold">✓ {data.pass} pass</span>
                          <span className="text-red-600 font-semibold">✗ {data.fail} fail</span>
                          <span className="ml-auto">{data.total_controls} controls</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Failing controls detail */}
                {Object.entries(compScores).map(([fw, data]) => {
                  const failing = Object.entries(data.controls ?? {}).filter(([,v]) => v === "FAIL");
                  if (failing.length === 0) return null;
                  const col = FW_COLOR[fw] ?? { badge: "bg-gray-100 text-gray-700" };
                  return (
                    <div key={fw} className="bg-white rounded-2xl border shadow-sm overflow-hidden">
                      <div className="px-6 py-4 border-b bg-gray-50 flex items-center gap-2">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-lg ${col.badge}`}>{fw}</span>
                        <p className="text-sm font-semibold text-gray-700">Failing Controls ({failing.length})</p>
                      </div>
                      <div className="divide-y max-h-80 overflow-y-auto">
                        {failing.map(([ctrl]) => (
                          <div key={ctrl} className="px-6 py-3 flex items-center gap-3">
                            <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
                            <span className="font-mono text-sm text-gray-600 w-20 shrink-0">{ctrl}</span>
                            <span className="text-sm text-gray-700 truncate">
                              {/* control title from inline data */}
                              {ctrl}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}

                {/* Compliance findings list */}
                <div className="bg-white rounded-2xl border shadow-sm overflow-hidden">
                  <div className="px-6 py-4 border-b flex items-center justify-between">
                    <p className="font-semibold">Compliance Findings ({compliance.length})</p>
                    <span className="text-xs text-gray-400">Findings mapped to framework controls</span>
                  </div>
                  <div className="divide-y max-h-[600px] overflow-y-auto">
                    {compliance.length === 0
                      ? <div className="p-8 text-center text-sm text-gray-400">No compliance findings</div>
                      : compliance.map(f => <FindingCard key={f.id} finding={f} />)
                    }
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Findings list (Security / Cost / Errors) ── */}
        {(tab === "security" || tab === "cost" || tab === "errors") && !loading && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-3 items-center">
              <select title="Filter by severity" value={sevFilter} onChange={e => setSev(e.target.value)} className="border rounded-lg px-3 py-1.5 text-sm bg-white">
                <option value="">All severities</option>
                {["Critical","High","Medium","Low"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select title="Filter by status" value={statusFilter} onChange={e => setStatus(e.target.value)} className="border rounded-lg px-3 py-1.5 text-sm bg-white">
                <option value="">All statuses</option>
                {["FAIL","WARNING","PASS","ERROR","SKIPPED"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <span className="ml-auto text-sm text-gray-500">{displayed.length} findings</span>
            </div>
            {displayed.length === 0
              ? <EmptyState tab={tab} />
              : displayed.map(f => <FindingCard key={f.id} finding={f} />)
            }
          </div>
        )}
      </main>

      <style jsx global>{`
        @media print {
          nav, button { display: none !important; }
          .bg-\\[\\#0f172a\\] { background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; color: white !important; }
          * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
      `}</style>
    </>
  );
}

function EmptyState({ tab }: { tab: Tab }) {
  const m: Record<string, [string, string]> = {
    security:   ["✅", "No security findings — all checks passed."],
    compliance: ["✅", "No compliance violations detected."],
    cost:       ["✅", "No idle or wasteful resources detected."],
    errors:     ["✅", "All checks completed successfully."],
  };
  const [icon, msg] = m[tab] ?? ["✅", "Nothing to show."];
  return (
    <div className="bg-white rounded-2xl border shadow-sm p-12 flex flex-col items-center gap-3 text-center">
      <span className="text-5xl">{icon}</span>
      <p className="text-sm text-gray-500">{msg}</p>
    </div>
  );
}

const STATUS_STYLE: Record<string, string> = {
  FAIL: "bg-red-100 text-red-700", WARNING: "bg-yellow-100 text-yellow-700",
  PASS: "bg-green-100 text-green-700", ERROR: "bg-gray-100 text-gray-600", SKIPPED: "bg-gray-100 text-gray-500",
};

function FindingCard({ finding: f }: { finding: Finding }) {
  const [open, setOpen]               = useState(false);
  const [showRemediation, setShowRem] = useState(false);
  const [remediation, setRemediation] = useState<Remediation | null>(f.ai_remediation ?? null);
  const [remLoading, setRemLoading]   = useState(false);

  async function fetchRemediation() {
    if (remediation) { setShowRem(true); return; }
    setRemLoading(true);
    try {
      const r = await api.remediateFinding(f.id);
      setRemediation(r);
      setShowRem(true);
    } catch { /* ignore */ }
    setRemLoading(false);
  }

  return (
    <div className="bg-white rounded-2xl border shadow-sm overflow-hidden">
      <button type="button" className="w-full text-left px-5 py-4" onClick={() => setOpen(o => !o)}>
        <div className="flex items-start gap-3">
          <span className={`w-2 h-2 rounded-full mt-2 shrink-0 ${SEV_DOT[f.severity] ?? "sev-dot-unknown"}`} />
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${STATUS_STYLE[f.status] ?? "bg-gray-100 text-gray-600"}`}>{f.status}</span>
              <span className="text-xs text-gray-400">{f.service}</span>
              <span className="text-xs text-gray-300">·</span>
              <span className="text-xs text-gray-400">{f.account_id}</span>
              {f.region && <><span className="text-xs text-gray-300">·</span><span className="text-xs text-gray-400">{f.region}</span></>}
              <span className={`ml-auto text-xs font-semibold ${SEV_TEXT[f.severity] ?? "text-gray-500"}`}>{f.severity}</span>
            </div>
            <p className="text-sm font-medium text-gray-800">{f.check_name}</p>
            <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{f.details}</p>
          </div>
          <span className="text-gray-300 shrink-0 text-sm">{open ? "▲" : "▼"}</span>
        </div>
      </button>

      {open && (
        <div className="border-t px-5 py-4 space-y-4 bg-gray-50">
          {f.details && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">DETAILS</p>
              <p className="text-sm text-gray-700 leading-relaxed">{f.details}</p>
            </div>
          )}
          {f.recommendation && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">RECOMMENDATION</p>
              <p className="text-sm text-gray-700 leading-relaxed">{f.recommendation}</p>
            </div>
          )}
          {Object.keys(f.compliance ?? {}).length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-2">COMPLIANCE CONTROLS</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(f.compliance).map(([k, v]) => {
                  const col = FW_COLOR[k]?.badge ?? "bg-gray-100 text-gray-700";
                  return <span key={k} className={`text-xs px-2 py-1 rounded-lg font-medium ${col}`}>{k}: {v}</span>;
                })}
              </div>
            </div>
          )}

          {/* AI Remediation */}
          {f.status === "FAIL" && (
            <div>
              <button type="button" onClick={fetchRemediation} disabled={remLoading}
                className="flex items-center gap-2 text-xs font-semibold text-indigo-600 hover:text-indigo-800 border border-indigo-200 bg-indigo-50 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50">
                {remLoading
                  ? <><span className="w-3 h-3 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />Generating…</>
                  : "🤖 AI Remediation Script"}
              </button>
            </div>
          )}

          {showRemediation && remediation && (
            <div className="mt-2 space-y-3 border border-indigo-200 rounded-xl bg-indigo-50/50 p-4">
              <button type="button" onClick={() => setShowRem(false)} className="float-right text-gray-400 hover:text-gray-600 text-lg leading-none">×</button>
              {remediation.explanation && (
                <p className="text-sm text-gray-700 leading-relaxed">{remediation.explanation}</p>
              )}
              {(remediation.steps ?? []).length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 mb-2">STEPS</p>
                  <ol className="list-decimal list-inside space-y-1">
                    {remediation.steps.map((s, i) => <li key={i} className="text-sm text-gray-700">{s}</li>)}
                  </ol>
                </div>
              )}
              {remediation.cli_script && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 mb-1">AWS CLI</p>
                  <pre className="text-xs bg-gray-900 text-green-300 rounded-xl p-3 overflow-x-auto leading-relaxed whitespace-pre-wrap">{remediation.cli_script}</pre>
                </div>
              )}
              {remediation.terraform_snippet && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 mb-1">TERRAFORM</p>
                  <pre className="text-xs bg-gray-900 text-blue-300 rounded-xl p-3 overflow-x-auto leading-relaxed whitespace-pre-wrap">{remediation.terraform_snippet}</pre>
                </div>
              )}
              {remediation.estimated_effort && (
                <p className="text-xs text-gray-500">⏱ Estimated effort: <strong>{remediation.estimated_effort}</strong></p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

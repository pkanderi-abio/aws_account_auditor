"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob, type Finding, type JobSummary } from "@/lib/api";
import { Nav } from "@/components/nav";

type Tab = "overview" | "security" | "compliance" | "cost" | "errors";

const SEV_COLOR: Record<string, string> = {
  Critical: "#dc2626", High: "#f97316", Medium: "#eab308", Low: "#22c55e",
};
const SEV_BG: Record<string, string> = {
  Critical: "#fef2f2", High: "#fff7ed", Medium: "#fefce8", Low: "#f0fdf4",
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
  const [job, setJob]             = useState<AuditJob | null>(null);
  const [summary, setSummary]     = useState<JobSummary | null>(null);
  const [allFindings, setAll]     = useState<Finding[]>([]);
  const [tab, setTab]             = useState<Tab>("overview");
  const [loading, setLoading]     = useState(true);
  const [sevFilter, setSev]       = useState("");
  const [statusFilter, setStatus] = useState("");

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
  }, [id, loadAll, router]);

  const { security, compliance, cost, errors } = categorise(allFindings);
  const sevCounts = { Critical: summary?.by_severity["Critical"] ?? 0, High: summary?.by_severity["High"] ?? 0, Medium: summary?.by_severity["Medium"] ?? 0, Low: summary?.by_severity["Low"] ?? 0 };
  const total = summary?.total ?? 0;
  const riskBar = (["Critical","High","Medium","Low"] as const).map(s => ({ sev: s, count: sevCounts[s], pct: total ? (sevCounts[s]/total)*100 : 0 })).filter(x => x.count > 0);

  const TABS: { id: Tab; label: string; count?: number }[] = [
    { id: "overview",   label: "Overview" },
    { id: "security",   label: "Security",   count: security.length },
    { id: "compliance", label: "Compliance", count: compliance.length },
    { id: "cost",       label: "Cost",       count: cost.length },
    { id: "errors",     label: "Errors",     count: errors.length },
  ];

  function tabFindings() {
    let list = tab === "security" ? security : tab === "compliance" ? compliance : tab === "cost" ? cost : tab === "errors" ? errors : [];
    if (sevFilter)    list = list.filter(f => f.severity === sevFilter);
    if (statusFilter) list = list.filter(f => f.status   === statusFilter);
    return list;
  }
  const displayed = tabFindings();
  const generatedAt = job ? new Date(job.created_at).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC" : "—";

  return (
    <>
      <Nav />

      {/* Dark header */}
      <div className="bg-[#0f172a] text-white">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center text-2xl shrink-0">🛡️</div>
              <div>
                <h1 className="text-2xl font-bold">AWS Security Audit Report</h1>
                <p className="text-slate-400 text-sm mt-0.5">Multi-account security, compliance &amp; cost findings</p>
              </div>
            </div>
            <button type="button" onClick={() => window.print()}
              className="shrink-0 flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
              🖨️ Save as PDF
            </button>
          </div>

          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-6 border-t border-slate-700 pt-6">
            <div><p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">GENERATED</p><p className="text-sm font-bold">{generatedAt}</p></div>
            <div><p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">ACCOUNTS SCANNED</p><p className="text-xl font-bold">{job?.accounts_audited?.length ?? 0}</p></div>
            <div><p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">TOTAL FINDINGS</p><p className="text-xl font-bold">{total}</p></div>
            <div><p className="text-xs text-slate-400 font-semibold tracking-widest mb-1">CRITICAL / HIGH</p>
              <p className={`text-xl font-bold ${(sevCounts.Critical + sevCounts.High) > 0 ? "text-orange-400" : "text-green-400"}`}>
                {sevCounts.Critical} / {sevCounts.High}
              </p>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-6 flex gap-1 border-t border-slate-700">
          {TABS.map(t => (
            <button key={t.id} type="button" onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${tab === t.id ? "border-orange-400 text-white" : "border-transparent text-slate-400 hover:text-white"}`}>
              {t.label}
              {t.count !== undefined && t.count > 0 && (
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${tab === t.id ? "bg-orange-500 text-white" : "bg-slate-600 text-slate-300"}`}>{t.count}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <button type="button" onClick={() => router.back()} className="text-sm text-gray-500 hover:text-gray-800">← Back</button>

        {loading && <p className="text-gray-400 text-sm">Loading findings…</p>}

        {/* Overview */}
        {tab === "overview" && !loading && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
              <div className="bg-white rounded-2xl border-t-4 border-indigo-500 shadow-sm p-5">
                <span className="text-2xl block mb-2">📋</span>
                <p className="text-3xl font-bold text-gray-800">{total}</p>
                <p className="text-xs text-gray-500 font-semibold tracking-wider mt-1">TOTAL FINDINGS</p>
              </div>
              {(["Critical","High","Medium","Low"] as const).map(s => (
                <div key={s} className="bg-white rounded-2xl border-t-4 shadow-sm p-5" style={{ borderTopColor: SEV_COLOR[s], backgroundColor: SEV_BG[s] }}>
                  <span className="w-3 h-3 rounded-full block mb-3" style={{ backgroundColor: SEV_COLOR[s] }} />
                  <p className="text-3xl font-bold" style={{ color: SEV_COLOR[s] }}>{sevCounts[s]}</p>
                  <p className="text-xs text-gray-500 font-semibold tracking-wider mt-1">{s.toUpperCase()}</p>
                </div>
              ))}
            </div>

            {total > 0 && (
              <div className="bg-white rounded-2xl border shadow-sm p-6">
                <p className="text-xs font-semibold text-gray-500 tracking-widest mb-3">RISK DISTRIBUTION</p>
                <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
                  {riskBar.map(({ sev, pct }) => (
                    <div key={sev} style={{ width: `${pct}%`, backgroundColor: SEV_COLOR[sev] }} />
                  ))}
                </div>
                <div className="flex gap-4 mt-3 flex-wrap">
                  {riskBar.map(({ sev, count }) => (
                    <span key={sev} className="flex items-center gap-1.5 text-xs text-gray-600">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLOR[sev] }} />
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
                        <div className="bg-brand h-2 rounded-full" style={{ width: `${Math.round((cnt/Math.max(total,1))*100)}%` }} />
                      </div>
                      <span className="text-sm font-semibold text-gray-700 w-6 text-right">{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="grid sm:grid-cols-3 gap-4">
              {([
                { label: "Security Findings",  icon: "🔐", list: security,   tid: "security",   border: "border-l-blue-500" },
                { label: "Compliance Findings", icon: "📋", list: compliance, tid: "compliance",  border: "border-l-purple-500" },
                { label: "Cost Findings",       icon: "💰", list: cost,       tid: "cost",        border: "border-l-green-500" },
              ] as const).map(({ label, icon, list, tid, border }) => (
                <button key={label} type="button" onClick={() => setTab(tid as Tab)}
                  className={`bg-white rounded-2xl border shadow-sm p-5 text-left hover:shadow-md transition-shadow border-l-4 ${border}`}>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl">{icon}</span>
                    <span className="text-2xl font-bold text-gray-800">{list.length}</span>
                  </div>
                  <p className="text-sm font-medium text-gray-700">{label}</p>
                  {list.length === 0
                    ? <p className="text-xs text-green-600 mt-1">✓ No issues found</p>
                    : <p className="text-xs text-gray-400 mt-1">Click to view →</p>}
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

        {/* Findings list */}
        {tab !== "overview" && !loading && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-3 items-center">
              <select value={sevFilter} onChange={e => setSev(e.target.value)} className="border rounded-lg px-3 py-1.5 text-sm bg-white">
                <option value="">All severities</option>
                {["Critical","High","Medium","Low"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={statusFilter} onChange={e => setStatus(e.target.value)} className="border rounded-lg px-3 py-1.5 text-sm bg-white">
                <option value="">All statuses</option>
                {["FAIL","WARNING","PASS","ERROR","SKIPPED"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <span className="ml-auto text-sm text-gray-500">{displayed.length} findings</span>
            </div>
            {displayed.length === 0 ? <EmptyState tab={tab} /> : displayed.map(f => <FindingCard key={f.id} finding={f} />)}
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
  const m: Record<Tab, [string, string]> = {
    overview:   ["✅",""],
    security:   ["✅","No security findings — all checks passed."],
    compliance: ["✅","No compliance violations detected."],
    cost:       ["✅","No idle or wasteful resources detected."],
    errors:     ["✅","All checks completed successfully."],
  };
  return (
    <div className="bg-white rounded-2xl border shadow-sm p-12 flex flex-col items-center gap-3 text-center">
      <span className="text-5xl">{m[tab][0]}</span>
      <p className="text-sm text-gray-500">{m[tab][1]}</p>
    </div>
  );
}

const STATUS_STYLE: Record<string, string> = {
  FAIL: "bg-red-100 text-red-700", WARNING: "bg-yellow-100 text-yellow-700",
  PASS: "bg-green-100 text-green-700", ERROR: "bg-gray-100 text-gray-600", SKIPPED: "bg-gray-100 text-gray-500",
};

function FindingCard({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="bg-white rounded-2xl border shadow-sm overflow-hidden">
      <button type="button" className="w-full text-left px-5 py-4" onClick={() => setOpen(o => !o)}>
        <div className="flex items-start gap-3">
          <span className="w-2 h-2 rounded-full mt-2 shrink-0" style={{ backgroundColor: SEV_COLOR[f.severity] ?? "#6b7280" }} />
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${STATUS_STYLE[f.status] ?? "bg-gray-100 text-gray-600"}`}>{f.status}</span>
              <span className="text-xs text-gray-400">{f.service}</span>
              <span className="text-xs text-gray-300">·</span>
              <span className="text-xs text-gray-400">{f.account_id}</span>
              {f.region && <><span className="text-xs text-gray-300">·</span><span className="text-xs text-gray-400">{f.region}</span></>}
              <span className="ml-auto text-xs font-semibold" style={{ color: SEV_COLOR[f.severity] }}>{f.severity}</span>
            </div>
            <p className="text-sm font-medium text-gray-800">{f.check_name}</p>
            <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{f.details}</p>
          </div>
          <span className="text-gray-300 shrink-0 text-sm">{open ? "▲" : "▼"}</span>
        </div>
      </button>
      {open && (f.recommendation || Object.keys(f.compliance ?? {}).length > 0) && (
        <div className="border-t px-5 py-4 space-y-3 bg-gray-50">
          {f.recommendation && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">RECOMMENDATION</p>
              <p className="text-sm text-gray-700 leading-relaxed">{f.recommendation}</p>
            </div>
          )}
          {Object.keys(f.compliance ?? {}).length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">COMPLIANCE</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(f.compliance).map(([k,v]) => (
                  <span key={k} className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded-lg font-medium">{k}: {v}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

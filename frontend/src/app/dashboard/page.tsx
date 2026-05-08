"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob, type JobSummary } from "@/lib/api";
import { Nav } from "@/components/nav";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEV_COLOR: Record<string, string> = { Critical: "#dc2626", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };
const SEV_BG:    Record<string, string> = { Critical: "#fef2f2", High: "#fff7ed", Medium: "#fefce8", Low: "#f0fdf4" };

const STATUS_STYLE: Record<string, { dot: string; badge: string; label: string }> = {
  completed: { dot: "bg-green-500",  badge: "bg-green-50 text-green-700 border-green-200",  label: "Completed"  },
  running:   { dot: "bg-blue-500 animate-pulse",   badge: "bg-blue-50 text-blue-700 border-blue-200",    label: "Running"    },
  pending:   { dot: "bg-yellow-400 animate-pulse", badge: "bg-yellow-50 text-yellow-700 border-yellow-200", label: "Pending"  },
  failed:    { dot: "bg-red-500",    badge: "bg-red-50 text-red-700 border-red-200",        label: "Failed"     },
};

export default function DashboardPage() {
  const router = useRouter();
  const [jobs, setJobs]         = useState<AuditJob[]>([]);
  const [summary, setSummary]   = useState<JobSummary | null>(null);
  const [triggering, setTriggering] = useState(false);
  const [error, setError]       = useState("");
  const [pollTimer, setPollTimer] = useState<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) router.replace("/auth/login");
    });
    loadJobs();
    return () => { if (pollTimer) clearInterval(pollTimer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadJobs() {
    try {
      const data = await api.listAudits();
      setJobs(data);
      const latest = data.find(j => j.status === "completed");
      if (latest) setSummary(await api.getSummary(latest.id));
    } catch { setError("Failed to load audits"); }
  }

  async function deleteAudit(id: string) {
    try { await api.deleteAudit(id); setJobs(prev => prev.filter(j => j.id !== id)); }
    catch { setError("Failed to delete audit"); }
  }

  async function clearFailed() {
    try { await api.deleteAudits("failed"); setJobs(prev => prev.filter(j => j.status !== "failed")); }
    catch { setError("Failed to clear audits"); }
  }

  async function triggerAudit() {
    setTriggering(true); setError("");
    try {
      await api.triggerAudit();
      await loadJobs();
      const t = setInterval(async () => {
        const fresh = await api.listAudits();
        setJobs(fresh);
        if (!fresh.find(j => j.status === "pending" || j.status === "running")) {
          clearInterval(t); setPollTimer(null); setTriggering(false);
          const latest = fresh.find(j => j.status === "completed");
          if (latest) setSummary(await api.getSummary(latest.id));
        }
      }, 5000);
      setPollTimer(t);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start audit");
      setTriggering(false);
    }
  }

  const sevData = summary
    ? ["Critical","High","Medium","Low"].map(s => ({ name: s, count: summary.by_severity[s] ?? 0 }))
    : [];
  const total   = summary?.total ?? 0;
  const hasSummary = sevData.some(d => d.count > 0);
  const lastRun = jobs.find(j => j.status === "completed");
  const hasRunning = jobs.some(j => j.status === "pending" || j.status === "running");

  return (
    <>
      <Nav />

      {/* ── Hero header ── */}
      <div className="bg-gradient-to-br from-[#0f172a] via-[#1e293b] to-[#0f172a] text-white">
        <div className="max-w-7xl mx-auto px-6 py-10">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <span className="text-3xl">🛡️</span>
                <h1 className="text-3xl font-extrabold tracking-tight">AWS Audit Dashboard</h1>
              </div>
              <p className="text-slate-400 text-sm">
                {lastRun
                  ? `Last audit ${new Date(lastRun.created_at).toLocaleString()} · ${lastRun.accounts_audited.length} account${lastRun.accounts_audited.length !== 1 ? "s" : ""}`
                  : "No audits run yet — click Run New Audit to get started"}
              </p>
            </div>
            <div className="flex items-center gap-3">
              {jobs.some(j => j.status === "failed") && (
                <button type="button" onClick={clearFailed}
                  className="text-sm text-slate-300 hover:text-white border border-slate-600 px-4 py-2 rounded-lg transition-colors">
                  Clear failed
                </button>
              )}
              <button type="button" onClick={triggerAudit} disabled={triggering || hasRunning}
                className="flex items-center gap-2 bg-orange-500 hover:bg-orange-400 disabled:opacity-50 text-white font-semibold px-5 py-2.5 rounded-xl shadow-lg shadow-orange-900/30 transition-all">
                {triggering || hasRunning
                  ? <><span className="w-3 h-3 rounded-full bg-white opacity-70 animate-ping" />Running audit…</>
                  : <><span>▶</span> Run New Audit</>}
              </button>
            </div>
          </div>

          {/* Top-line stats */}
          {hasSummary && (
            <div className="mt-8 grid grid-cols-2 sm:grid-cols-4 gap-4">
              {sevData.map(({ name, count }) => (
                <div key={name} className="rounded-2xl p-4 border border-slate-700 bg-slate-800/50 backdrop-blur">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLOR[name] }} />
                    <span className="text-xs text-slate-400 font-semibold tracking-widest">{name.toUpperCase()}</span>
                  </div>
                  <p className="text-3xl font-extrabold" style={{ color: SEV_COLOR[name] }}>{count}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
            <span className="text-red-500 text-lg">⚠</span>
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        {/* Charts row */}
        {hasSummary && summary && (
          <div className="grid lg:grid-cols-2 gap-6">
            {/* Bar chart */}
            <div className="bg-white rounded-2xl border shadow-sm p-6">
              <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">FINDINGS BY SEVERITY</p>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={sevData} barCategoryGap="35%">
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: "#f8fafc" }}
                    contentStyle={{ border: "1px solid #e2e8f0", borderRadius: 12, fontSize: 12 }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {sevData.map(({ name }) => <Cell key={name} fill={SEV_COLOR[name]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Service breakdown */}
            <div className="bg-white rounded-2xl border shadow-sm p-6">
              <p className="text-xs font-semibold text-gray-500 tracking-widest mb-4">FINDINGS BY SERVICE</p>
              {Object.keys(summary.by_service).length === 0
                ? <p className="text-sm text-gray-400 mt-8 text-center">No service data</p>
                : <div className="space-y-3">
                    {Object.entries(summary.by_service)
                      .sort(([,a],[,b]) => b - a).slice(0, 7)
                      .map(([svc, cnt]) => (
                        <div key={svc} className="flex items-center gap-3">
                          <span className="text-sm text-gray-600 w-32 truncate shrink-0">{svc}</span>
                          <div className="flex-1 bg-gray-100 rounded-full h-2">
                            <div className="bg-brand h-2 rounded-full transition-all"
                              style={{ width: `${Math.round((cnt / Math.max(total, 1)) * 100)}%` }} />
                          </div>
                          <span className="text-sm font-bold text-gray-700 w-6 text-right shrink-0">{cnt}</span>
                        </div>
                      ))}
                  </div>}
            </div>
          </div>
        )}

        {/* Severity stat cards (when no summary show placeholder) */}
        {!hasSummary && jobs.length === 0 && (
          <div className="grid sm:grid-cols-3 gap-4">
            {[
              { icon: "🔍", title: "Multi-account scanning", desc: "Audit every AWS account simultaneously across IAM, S3, EC2, RDS, and more." },
              { icon: "🛡️", title: "Security & compliance", desc: "CIS, PCI-DSS, and SOC 2 checks. Security Hub and GuardDuty integrated." },
              { icon: "💰", title: "Cost optimisation", desc: "Surface idle resources and reservation opportunities alongside security findings." },
            ].map(({ icon, title, desc }) => (
              <div key={title} className="bg-white rounded-2xl border p-6 shadow-sm">
                <span className="text-3xl mb-3 block">{icon}</span>
                <p className="font-semibold mb-1">{title}</p>
                <p className="text-sm text-gray-500 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        )}

        {/* Recent audits table */}
        <div className="bg-white rounded-2xl border shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b flex items-center justify-between">
            <p className="font-semibold">Recent Audits</p>
            <span className="text-xs text-gray-400">{jobs.length} total</span>
          </div>
          {jobs.length === 0 ? (
            <div className="px-6 py-16 text-center">
              <span className="text-5xl block mb-4">🚀</span>
              <p className="font-medium text-gray-700 mb-1">No audits yet</p>
              <p className="text-sm text-gray-400">Click <strong>Run New Audit</strong> above to scan your AWS environment.</p>
            </div>
          ) : (
            <div className="divide-y">
              {jobs.map(job => {
                const st = STATUS_STYLE[job.status] ?? STATUS_STYLE.failed;
                const dur = job.started_at && job.completed_at
                  ? Math.round((new Date(job.completed_at).getTime() - new Date(job.started_at).getTime()) / 1000)
                  : null;
                return (
                  <div key={job.id} className="px-6 py-4 flex items-center gap-4 hover:bg-gray-50 transition-colors">
                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${st.dot}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800">{new Date(job.created_at).toLocaleString()}</p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {job.accounts_audited.length} account{job.accounts_audited.length !== 1 ? "s" : ""}
                        {job.total_findings > 0 ? ` · ${job.total_findings} findings` : ""}
                        {dur ? ` · ${dur}s` : ""}
                        {job.error_message && <span className="text-red-400"> · {job.error_message.slice(0, 60)}…</span>}
                      </p>
                    </div>
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${st.badge}`}>{st.label}</span>
                    {job.status === "completed" && (
                      <a href={`/audits/${job.id}`}
                        className="text-sm font-medium text-brand hover:text-brand-dark shrink-0">
                        View report →
                      </a>
                    )}
                    {(job.status === "failed" || job.status === "completed") && (
                      <button type="button" onClick={() => deleteAudit(job.id)}
                        className="text-gray-300 hover:text-red-400 transition-colors shrink-0 text-sm px-1">✕</button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </>
  );
}

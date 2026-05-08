import { supabase } from "./supabase";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function authHeaders(): Promise<HeadersInit> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  return token ? { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } : { "Content-Type": "application/json" };
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers = await authHeaders();
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Request failed");
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  // Config & accounts
  getConfig: ()                  => req<AwsConfig>("GET",    "/api/config"),
  saveConfig: (b: AwsConfigIn)   => req<AwsConfig>("PUT",    "/api/config", b),
  listAccounts: ()               => req<AwsAccount[]>("GET", "/api/accounts"),
  addAccount: (b: AwsAccountIn)  => req<AwsAccount>("POST",  "/api/accounts", b),
  removeAccount: (id: string)    => req<void>("DELETE",       `/api/accounts/${id}`),
  deleteConfig: ()               => req<void>("DELETE",      "/api/config"),
  // Audits
  triggerAudit: ()               => req<AuditJob>("POST",    "/api/audits"),
  listAudits: ()                 => req<AuditJob[]>("GET",   "/api/audits"),
  deleteAudit: (id: string)      => req<void>("DELETE",      `/api/audits/${id}`),
  deleteAudits: (status?: string) => req<void>("DELETE",     `/api/audits${status ? `?status=${status}` : ""}`),
  getAudit: (id: string)         => req<AuditJob>("GET",     `/api/audits/${id}`),
  getFindings: (id: string, params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return req<Finding[]>("GET", `/api/audits/${id}/findings${qs}`);
  },
  getSummary: (id: string)       => req<JobSummary>("GET",   `/api/audits/${id}/summary`),
  // AI & compliance
  ollamaHealth: ()               => req<OllamaHealth>("GET", "/api/ai/health"),
  analyzeJob: (id: string)       => req<AiAnalysis>("POST",  `/api/ai/analyze/${id}`),
  getAnalysis: (id: string)      => req<AiAnalysis>("GET",   `/api/ai/analysis/${id}`),
  remediateFinding: (fid: string) => req<Remediation>("POST", `/api/ai/remediate/${fid}`),
  generateReport: (id: string)   => req<{ report: string }>("POST", `/api/ai/report/${id}`),
  getComplianceScores: (id: string) => req<ComplianceScores>("GET", `/api/ai/compliance/${id}`),
  // Streaming chat — returns raw Response for SSE
  chatStream: async (jobId: string, question: string, history?: ChatMessage[]) => {
    const headers = await authHeaders();
    return fetch(`${BASE}/api/ai/chat/${jobId}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ question, history: history ?? [] }),
    });
  },
};

// ── Types mirroring backend schemas ──────────────────────────────────────────

export interface AwsConfig {
  id: string; deployer_role_arn: string; deployer_external_id: string;
  audit_role_name: string; audit_role_external_id: string;
  regions: string[]; use_organizations: boolean; enabled_audits: string[];
  created_at: string; updated_at: string;
}
export type AwsConfigIn = Omit<AwsConfig, "id" | "created_at" | "updated_at">;
export interface AwsAccount { id: string; account_id: string; account_name: string; created_at: string; }
export type AwsAccountIn = Omit<AwsAccount, "id" | "created_at">;
export interface AuditJob {
  id: string; status: string; started_at: string | null; completed_at: string | null;
  created_at: string; accounts_audited: string[]; total_findings: number; error_message: string | null;
}
export interface Finding {
  id: string; account_id: string; region: string; service: string; check_name: string;
  status: string; severity: string; finding_type: string; details: string;
  recommendation: string; timestamp: string | null; compliance: Record<string, string>;
  ai_remediation?: Remediation | null;
}
export interface JobSummary { total: number; by_severity: Record<string, number>; by_service: Record<string, number>; accounts_audited: string[]; }

// AI types
export interface AiAnalysis {
  headline: string; risk_level: string; summary: string;
  top_risks: string[]; quick_wins: string[]; narrative: string;
  executive_report?: string | null; created_at?: string | null;
}
export interface Remediation {
  explanation: string; steps: string[]; cli_script: string;
  terraform_snippet: string; estimated_effort: string; risk_if_not_fixed: string;
}
export interface OllamaHealth {
  status: string; ollama_url: string; model: string;
  model_available: boolean; available_models?: string[]; error?: string;
}
export interface ComplianceFrameworkScore {
  framework_name: string; score: number; pass: number; fail: number;
  total_controls: number; controls: Record<string, string>;
}
export type ComplianceScores = Record<string, ComplianceFrameworkScore>;

export interface ChatMessage { role: "user" | "assistant"; content: string; }

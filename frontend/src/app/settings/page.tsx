"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AwsConfig, type AwsAccount } from "@/lib/api";
import { Nav } from "@/components/nav";
import clsx from "clsx";

type Tab = "overview" | "cleanup" | "suggestions";

export default function SettingsPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("overview");
  const [config, setConfig] = useState<AwsConfig | null>(null);
  const [accounts, setAccounts] = useState<AwsAccount[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) { router.replace("/auth/login"); return; }
    });
    api.getConfig().then(setConfig).catch(() => {});
    api.listAccounts().then(setAccounts).catch(() => {});
  }, [router]);

  async function resetConfig() {
    try {
      await api.deleteConfig();
      setConfig(null);
      setAccounts([]);
      setConfirming(false);
      setMsg({ ok: true, text: "AWS configuration removed. You can re-configure at any time from Settings → AWS Setup." });
    } catch {
      setMsg({ ok: false, text: "Failed to remove configuration." });
    }
  }

  async function clearAllAudits() {
    try {
      await api.deleteAudits();
      setConfirming(false);
      setMsg({ ok: true, text: "All audit history cleared." });
    } catch {
      setMsg({ ok: false, text: "Failed to clear audit history." });
    }
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: "overview",    label: "Overview" },
    { id: "cleanup",     label: "Cleanup" },
    { id: "suggestions", label: "Suggestions" },
  ];

  return (
    <>
      <Nav />

      {/* Hero header */}
      <div className="bg-gradient-to-br from-[#0f172a] via-[#1e293b] to-[#0f172a] text-white">
        <div className="max-w-3xl mx-auto px-6 py-10">
          <div className="flex items-center gap-3 mb-1">
            <span className="text-3xl">⚙️</span>
            <h1 className="text-3xl font-extrabold tracking-tight">Settings</h1>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            {config
              ? `Connected to AWS · ${accounts.length} account${accounts.length !== 1 ? "s" : ""} configured`
              : "No AWS configuration — run the setup wizard to get started"}
          </p>

          {/* Tab bar inside hero */}
          <div className="flex gap-1 mt-8 border-b border-slate-700">
            {TABS.map(t => (
              <button key={t.id} type="button"
                onClick={() => { setTab(t.id); setMsg(null); }}
                className={clsx(
                  "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors",
                  tab === t.id
                    ? "border-orange-400 text-white"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                )}>
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <main className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        {msg && (
          <div className={clsx("flex items-start gap-3 text-sm rounded-xl p-4 border",
            msg.ok ? "bg-green-50 border-green-200 text-green-800" : "bg-red-50 border-red-200 text-red-700")}>
            <span className="text-lg">{msg.ok ? "✓" : "⚠"}</span>
            <p>{msg.text}</p>
          </div>
        )}

        {/* ── Overview ── */}
        {tab === "overview" && (
          <div className="space-y-4">
            {config ? (
              <>
                <Section title="AWS Connection" icon="🔗">
                  <Row label="Deployer Role ARN"    value={config.deployer_role_arn} mono />
                  <Row label="Deployer ExternalId"  value={config.deployer_external_id} mono />
                  <Row label="Audit Role Name"      value={config.audit_role_name} mono />
                  <Row label="Audit ExternalId"     value={config.audit_role_external_id} mono />
                  <Row label="Regions"              value={config.regions.join(", ")} />
                  <Row label="Modules"              value={config.enabled_audits.join(", ")} />
                  <Row label="Auto-discover via Org" value={config.use_organizations ? "Yes" : "No"} />
                </Section>

                <Section title={`Accounts (${accounts.length})`} icon="🏢">
                  {accounts.length === 0
                    ? <p className="text-sm text-gray-400">No accounts added.</p>
                    : <div className="divide-y">
                        {accounts.map(a => (
                          <div key={a.id} className="flex items-center justify-between py-2">
                            <span className="font-mono text-sm bg-gray-100 px-2 py-0.5 rounded text-gray-700">{a.account_id}</span>
                            {a.account_name && <span className="text-gray-500 text-sm">{a.account_name}</span>}
                          </div>
                        ))}
                      </div>
                  }
                  <div className="pt-2">
                    <a href="/config" className="text-sm font-medium text-brand hover:underline">Edit accounts →</a>
                  </div>
                </Section>
              </>
            ) : (
              <div className="rounded-2xl border-2 border-dashed border-gray-200 p-10 text-center space-y-3">
                <span className="text-4xl block">☁️</span>
                <p className="text-sm text-gray-500">No AWS configuration found.</p>
                <a href="/config"
                  className="inline-block text-sm font-semibold bg-brand text-white px-4 py-2 rounded-xl hover:bg-brand-dark transition-colors">
                  Run setup wizard →
                </a>
              </div>
            )}
          </div>
        )}

        {/* ── Cleanup ── */}
        {tab === "cleanup" && (
          <div className="space-y-4">
            <Section title="Audit History" icon="📋">
              <p className="text-sm text-gray-500 mb-3">
                Remove audit records and findings from the database. This does not affect your AWS environment.
              </p>
              <div className="flex gap-3">
                <DangerButton
                  label="Clear failed audits"
                  description="Delete all failed audit records."
                  onConfirm={() => api.deleteAudits("failed").then(() => setMsg({ ok: true, text: "Failed audits cleared." })).catch(() => setMsg({ ok: false, text: "Failed." }))}
                />
                <DangerButton
                  label="Clear all audit history"
                  description="Delete every audit record and all findings."
                  onConfirm={clearAllAudits}
                />
              </div>
            </Section>

            <Section title="AWS Configuration" icon="☁️">
              <p className="text-sm text-gray-500 mb-3">
                Remove your stored AWS config and account list. The IAM roles in AWS are <strong>not</strong> deleted — use the commands below for that.
              </p>
              <DangerButton
                label="Remove AWS configuration"
                description="Wipes deployer role ARN, ExternalIds, regions, and all accounts from the database."
                onConfirm={resetConfig}
              />
            </Section>

            <Section title="Remove IAM Roles from AWS" icon="🗑️">
              <p className="text-sm text-gray-500 mb-3">
                Run these commands to delete the CloudFormation stacks and IAM roles created by the setup wizard.
              </p>
              <CodeBlock label="Delete AuditDeployer role (management account)">
                {`aws cloudformation delete-stack \\
  --stack-name AuditDeployer \\
  --region us-east-1`}
              </CodeBlock>
              <CodeBlock label="Delete AuditRole StackSet instances (all member accounts)">
                {`aws cloudformation delete-stack-instances \\
  --stack-set-name AuditRole \\
  --deployment-targets OrganizationalUnitIds=<YOUR_OU_ID> \\
  --regions us-east-1 \\
  --no-retain-stacks

aws cloudformation delete-stack-set \\
  --stack-set-name AuditRole`}
              </CodeBlock>
              <CodeBlock label="Delete the SaaS app IAM user (if created)">
                {`aws iam delete-user-policy \\
  --user-name auditor-saas-app \\
  --policy-name AllowAssumeAuditDeployer

aws iam delete-access-key \\
  --user-name auditor-saas-app \\
  --access-key-id AKIAZI2LGVHSOLHISGNO

aws iam delete-user --user-name auditor-saas-app`}
              </CodeBlock>
            </Section>
          </div>
        )}

        {/* ── Suggestions ── */}
        {tab === "suggestions" && (
          <div className="space-y-4">
            <Section title="Audit Coverage" icon="🔍">
              <Suggestion
                icon="🌍"
                title="Add more regions"
                body="You're currently auditing 6 regions. Consider adding eu-west-1 and ap-southeast-1 for broader coverage if you deploy workloads there."
                action={config ? { label: "Edit regions →", href: "/config" } : undefined}
              />
              <Suggestion
                icon="🏢"
                title="Enable AWS Organizations discovery"
                body="Instead of adding account IDs manually, enable auto-discovery to automatically audit every active account in your org — including accounts added in the future."
                action={config ? { label: "Edit config →", href: "/config" } : undefined}
              />
            </Section>

            <Section title="Security Posture" icon="🛡️">
              <Suggestion
                icon="🔄"
                title="Schedule regular audits"
                body="Run audits on a regular cadence (daily or weekly) to catch drift. Use the API to trigger audits from a cron job or CI pipeline."
                code={`curl -X POST ${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/api/audits \\
  -H "Authorization: Bearer <your-token>"`}
              />
              <Suggestion
                icon="📊"
                title="Focus on Critical and High findings first"
                body='Use the severity filter on Audit Results to isolate Critical and High findings. These typically include public S3 buckets, open security groups, and missing MFA on IAM users.'
              />
              <Suggestion
                icon="🔐"
                title="Rotate the Deployer ExternalId periodically"
                body="The ExternalId on your AuditDeployer role acts as a shared secret. Rotate it by updating the CloudFormation stack and updating the value in Settings → AWS Setup."
              />
            </Section>

            <Section title="Modules" icon="🧩">
              <Suggestion
                icon="💰"
                title="Cost optimization findings"
                body="The cost_optimization module flags idle EC2 instances, unattached EBS volumes, and underutilised RDS instances. Enable it if you haven't already."
                action={config ? { label: "Edit modules →", href: "/config" } : undefined}
              />
              <Suggestion
                icon="🛡️"
                title="Security Hub & GuardDuty"
                body="The security_hub and cloudtrail modules pull findings directly from AWS Security Hub and GuardDuty. Make sure both services are enabled in each audited account and region."
              />
            </Section>
          </div>
        )}
      </main>
    </>
  );
}

// ── Small shared components ────────────────────────────────────────────────

function Section({ title, children, icon }: { title: string; children: React.ReactNode; icon?: string }) {
  return (
    <div className="bg-white rounded-2xl border shadow-sm overflow-hidden">
      <div className="px-6 py-4 border-b bg-gray-50/60 flex items-center gap-2">
        {icon && <span className="text-base">{icon}</span>}
        <h2 className="font-semibold text-sm text-gray-700 tracking-wide">{title}</h2>
      </div>
      <div className="p-6 space-y-3">{children}</div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b last:border-0">
      <span className="text-sm text-gray-500 shrink-0 w-44">{label}</span>
      <span className={clsx("text-sm text-right break-all", mono ? "font-mono text-xs bg-gray-100 px-2 py-0.5 rounded text-gray-700" : "text-gray-800")}>{value}</span>
    </div>
  );
}

function DangerButton({ label, description, onConfirm }: { label: string; description: string; onConfirm: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="bg-red-50 border border-red-200 rounded-xl p-4 space-y-2 flex-1">
      <p className="text-sm font-semibold text-red-700">{label}</p>
      <p className="text-xs text-gray-500 leading-relaxed">{description}</p>
      {open ? (
        <div className="flex gap-2 pt-1">
          <button type="button" onClick={() => { setOpen(false); onConfirm(); }}
            className="text-xs bg-red-600 text-white px-3 py-1.5 rounded-lg hover:bg-red-700 font-medium transition-colors">
            Yes, delete
          </button>
          <button type="button" onClick={() => setOpen(false)}
            className="text-xs text-gray-600 bg-white border px-3 py-1.5 rounded-lg hover:bg-gray-50 transition-colors">
            Cancel
          </button>
        </div>
      ) : (
        <button type="button" onClick={() => setOpen(true)}
          className="text-xs text-red-600 border border-red-300 bg-white px-3 py-1.5 rounded-lg hover:bg-red-50 font-medium transition-colors">
          {label}
        </button>
      )}
    </div>
  );
}

function CodeBlock({ label, children }: { label: string; children: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="space-y-1 mb-3">
      <p className="text-xs text-gray-500">{label}</p>
      <div className="relative bg-gray-900 rounded-xl">
        <pre className="text-xs text-green-300 p-4 overflow-x-auto leading-relaxed">{children}</pre>
        <button type="button" onClick={copy}
          className="absolute top-2 right-2 text-xs text-gray-400 hover:text-white bg-gray-700 px-2 py-1 rounded">
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function Suggestion({ icon, title, body, action, code }: {
  icon: string; title: string; body: string;
  action?: { label: string; href: string };
  code?: string;
}) {
  return (
    <div className="flex gap-4 py-4 border-b last:border-0">
      <span className="text-2xl shrink-0 mt-0.5">{icon}</span>
      <div className="space-y-1.5 flex-1 min-w-0">
        <p className="text-sm font-semibold text-gray-800">{title}</p>
        <p className="text-sm text-gray-500 leading-relaxed">{body}</p>
        {code && (
          <pre className="text-xs bg-gray-900 text-green-300 rounded-xl p-3 mt-2 overflow-x-auto leading-relaxed">{code}</pre>
        )}
        {action && (
          <a href={action.href} className="inline-block text-sm font-medium text-brand hover:underline mt-1">{action.label}</a>
        )}
      </div>
    </div>
  );
}

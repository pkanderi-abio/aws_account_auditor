"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AwsConfigIn, type AwsAccount } from "@/lib/api";
import { Nav } from "@/components/nav";
import clsx from "clsx";

const ALL_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1",
];
const ALL_AUDITS = ["iam", "network", "exposure", "cloudtrail", "security_hub", "cost_optimization", "cyber"];

const DEFAULT_CONFIG: AwsConfigIn = {
  deployer_role_arn: "",
  deployer_external_id: "",
  audit_role_name: "AuditRole",
  audit_role_external_id: "audit-access",
  regions: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
  use_organizations: false,
  enabled_audits: [...ALL_AUDITS],
};

const STEPS = [
  { id: 1, label: "Deploy IAM Roles" },
  { id: 2, label: "Connect AWS"     },
  { id: 3, label: "Add Accounts"    },
];

export default function ConfigPage() {
  const router = useRouter();
  const [step, setStep]       = useState(1);
  const [config, setConfig]   = useState<AwsConfigIn>(DEFAULT_CONFIG);
  const [accounts, setAccounts] = useState<AwsAccount[]>([]);
  const [newId, setNewId]     = useState("");
  const [newName, setNewName] = useState("");
  const [saving, setSaving]   = useState(false);
  const [msg, setMsg]         = useState<{ ok: boolean; text: string } | null>(null);
  const [configured, setConfigured] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) { router.replace("/auth/login"); return; }
    });
    api.getConfig()
      .then(c => {
        setConfig({
          deployer_role_arn: c.deployer_role_arn,
          deployer_external_id: c.deployer_external_id,
          audit_role_name: c.audit_role_name,
          audit_role_external_id: c.audit_role_external_id,
          regions: c.regions,
          use_organizations: c.use_organizations,
          enabled_audits: c.enabled_audits,
        });
        setConfigured(true);
        setStep(3); // already configured, jump to accounts
      })
      .catch(() => {/* first-time user */});
    api.listAccounts().then(setAccounts).catch(() => {});
  }, []);

  function toggle<T>(arr: T[], item: T) {
    return arr.includes(item) ? arr.filter(x => x !== item) : [...arr, item];
  }

  async function saveConfig(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true); setMsg(null);
    try {
      await api.saveConfig(config);
      setConfigured(true);
      setMsg({ ok: true, text: "AWS connection saved successfully." });
      setStep(3);
    } catch (err: unknown) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Save failed" });
    } finally { setSaving(false); }
  }

  async function addAccount(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    try {
      const acc = await api.addAccount({ account_id: newId.trim(), account_name: newName.trim() });
      setAccounts(prev => [...prev, acc]);
      setNewId(""); setNewName("");
    } catch (err: unknown) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed to add account" });
    }
  }

  async function removeAccount(accountId: string) {
    await api.removeAccount(accountId);
    setAccounts(prev => prev.filter(a => a.account_id !== accountId));
  }

  return (
    <>
      <Nav />
      <main className="max-w-3xl mx-auto px-6 py-10 space-y-8">
        <div>
          <h1 className="text-2xl font-bold">AWS Setup</h1>
          <p className="text-gray-500 mt-1 text-sm">Connect your AWS environment in three steps.</p>
        </div>

        {/* ── Stepper ── */}
        <div className="flex items-center gap-0">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex items-center flex-1 last:flex-none">
              <button
                type="button"
                onClick={() => (s.id < step || configured) && setStep(s.id)}
                className={clsx(
                  "flex items-center gap-2 text-sm font-medium transition-colors",
                  step === s.id ? "text-brand" : s.id < step || configured ? "text-gray-600 hover:text-brand cursor-pointer" : "text-gray-300 cursor-default"
                )}
              >
                <span className={clsx(
                  "w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-colors",
                  step === s.id ? "border-brand bg-brand text-white" :
                  s.id < step || configured ? "border-green-500 bg-green-500 text-white" : "border-gray-300 text-gray-300"
                )}>
                  {(s.id < step || configured) && s.id !== step ? "✓" : s.id}
                </span>
                {s.label}
              </button>
              {i < STEPS.length - 1 && (
                <div className={clsx("flex-1 h-0.5 mx-3", step > s.id || configured ? "bg-green-400" : "bg-gray-200")} />
              )}
            </div>
          ))}
        </div>

        {msg && (
          <p className={clsx("text-sm rounded-lg p-3", msg.ok ? "bg-green-50 text-green-800" : "bg-red-50 text-red-700")}>
            {msg.text}
          </p>
        )}

        {/* ── Step 1: Deploy IAM Roles ── */}
        {step === 1 && (
          <div className="bg-white rounded-2xl border shadow-sm p-6 space-y-5">
            <div>
              <h2 className="font-semibold text-lg mb-1">Step 1 — Deploy IAM roles to your AWS account</h2>
              <p className="text-sm text-gray-500">
                Two CloudFormation templates need to be deployed. This gives the auditor read-only access to your accounts.
              </p>
            </div>

            <div className="space-y-4">
              {/* Template A */}
              <div className="rounded-xl border p-4 space-y-2">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-medium text-sm">1A · Management account — AuditDeployer role</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      Deploy <code className="bg-gray-100 px-1 rounded">saas_customer_role.yaml</code> to your <strong>management account only</strong>.
                      This creates a role that trusts the auditor platform to assume it.
                    </p>
                  </div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3 font-mono text-xs text-gray-700 space-y-1">
                  <p className="text-gray-400"># AWS CLI — replace the ExternalId with a secret string you choose</p>
                  <p>aws cloudformation deploy \</p>
                  <p className="pl-4">--template-file saas_customer_role.yaml \</p>
                  <p className="pl-4">--stack-name AuditDeployer \</p>
                  <p className="pl-4">--capabilities CAPABILITY_NAMED_IAM \</p>
                  <p className="pl-4">--parameter-overrides \</p>
                  <p className="pl-6">SaaSAwsAccountId=<span className="text-blue-600">{"<auditor-platform-account-id>"}</span> \</p>
                  <p className="pl-6">DeployerExternalId=<span className="text-blue-600">{"<your-secret-string>"}</span></p>
                </div>
                <p className="text-xs text-gray-500">
                  After deploy: copy the <code className="bg-gray-100 px-1 rounded">DeployerRoleArn</code> output — you'll paste it in Step 2.
                </p>
              </div>

              {/* Template B */}
              <div className="rounded-xl border p-4 space-y-2">
                <div>
                  <p className="font-medium text-sm">1B · All sub-accounts — AuditRole (via StackSet)</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Deploy <code className="bg-gray-100 px-1 rounded">auditrole_stackset_template.yaml</code> to every account you want audited.
                    Use a CloudFormation StackSet to deploy across your entire organization at once.
                  </p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3 font-mono text-xs text-gray-700 space-y-1">
                  <p className="text-gray-400"># Deploy to all accounts in your organization</p>
                  <p>aws cloudformation create-stack-set \</p>
                  <p className="pl-4">--stack-set-name AuditRole \</p>
                  <p className="pl-4">--template-body file://auditrole_stackset_template.yaml \</p>
                  <p className="pl-4">--capabilities CAPABILITY_NAMED_IAM \</p>
                  <p className="pl-4">--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false</p>
                </div>
                <p className="text-xs text-gray-500">
                  The AuditRole is <strong>read-only</strong> — it has no write permissions to any resource.
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button type="button" onClick={() => setStep(2)}
                className="bg-brand text-white px-6 py-2 rounded-lg font-medium hover:bg-brand-dark">
                Roles deployed → Continue
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2: Connect AWS ── */}
        {step === 2 && (
          <div className="bg-white rounded-2xl border shadow-sm p-6 space-y-5">
            <div>
              <h2 className="font-semibold text-lg mb-1">Step 2 — Enter your role details</h2>
              <p className="text-sm text-gray-500">
                These values come from the CloudFormation outputs in Step 1.
              </p>
            </div>

            <form onSubmit={saveConfig} className="space-y-5">
              <Field label="Deployer Role ARN"
                hint="From the AuditDeployer stack output — arn:aws:iam::YOUR-MGMT-ACCOUNT:role/AuditDeployer">
                <input required value={config.deployer_role_arn}
                  onChange={e => setConfig(c => ({ ...c, deployer_role_arn: e.target.value }))}
                  placeholder="arn:aws:iam::123456789012:role/AuditDeployer"
                  className="input" />
              </Field>

              <Field label="Deployer ExternalId"
                hint="The secret string you chose when running the CloudFormation deploy in Step 1A">
                <input required value={config.deployer_external_id}
                  onChange={e => setConfig(c => ({ ...c, deployer_external_id: e.target.value }))}
                  placeholder="your-secret-string"
                  className="input" />
              </Field>

              <div className="grid grid-cols-2 gap-4">
                <Field label="Audit Role Name" hint="Default: AuditRole">
                  <input required value={config.audit_role_name}
                    onChange={e => setConfig(c => ({ ...c, audit_role_name: e.target.value }))}
                    placeholder="AuditRole"
                    className="input" />
                </Field>
                <Field label="Audit Role ExternalId" hint="Default: audit-access">
                  <input required value={config.audit_role_external_id}
                    onChange={e => setConfig(c => ({ ...c, audit_role_external_id: e.target.value }))}
                    placeholder="audit-access"
                    className="input" />
                </Field>
              </div>

              <Field label="Regions to audit">
                <div className="flex flex-wrap gap-x-4 gap-y-2 pt-1">
                  {ALL_REGIONS.map(r => (
                    <label key={r} className="flex items-center gap-1.5 text-sm cursor-pointer">
                      <input type="checkbox" checked={config.regions.includes(r)}
                        onChange={() => setConfig(c => ({ ...c, regions: toggle(c.regions, r) }))}
                        className="rounded" />
                      {r}
                    </label>
                  ))}
                </div>
              </Field>

              <Field label="Audit modules">
                <div className="flex flex-wrap gap-x-4 gap-y-2 pt-1">
                  {ALL_AUDITS.map(a => (
                    <label key={a} className="flex items-center gap-1.5 text-sm cursor-pointer">
                      <input type="checkbox" checked={config.enabled_audits.includes(a)}
                        onChange={() => setConfig(c => ({ ...c, enabled_audits: toggle(c.enabled_audits, a) }))}
                        className="rounded" />
                      {a}
                    </label>
                  ))}
                </div>
              </Field>

              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={config.use_organizations}
                  onChange={e => setConfig(c => ({ ...c, use_organizations: e.target.checked }))}
                  className="rounded" />
                <span>Auto-discover accounts from AWS Organizations</span>
              </label>

              <div className="flex items-center justify-between pt-2">
                <button type="button" onClick={() => setStep(1)}
                  className="text-sm text-gray-500 hover:text-gray-800">← Back</button>
                <button type="submit" disabled={saving}
                  className="bg-brand text-white px-6 py-2 rounded-lg font-medium hover:bg-brand-dark disabled:opacity-50">
                  {saving ? "Saving…" : "Save & Continue →"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* ── Step 3: Add Accounts ── */}
        {step === 3 && (
          <div className="bg-white rounded-2xl border shadow-sm p-6 space-y-5">
            <div>
              <h2 className="font-semibold text-lg mb-1">Step 3 — Add AWS accounts to audit</h2>
              <p className="text-sm text-gray-500">
                {config.use_organizations
                  ? "Auto-discovery is enabled — accounts are pulled from AWS Organizations automatically."
                  : "Add each account ID you want to audit. The AuditRole must be deployed to each one."}
              </p>
            </div>

            {!config.use_organizations && (
              <>
                <form onSubmit={addAccount} className="flex gap-2">
                  <input required value={newId} onChange={e => setNewId(e.target.value)}
                    placeholder="Account ID (12 digits)" pattern="\d{12}"
                    className="input flex-1" />
                  <input value={newName} onChange={e => setNewName(e.target.value)}
                    placeholder="Label (optional)" className="input w-44" />
                  <button type="submit"
                    className="bg-brand text-white px-4 py-2 rounded-lg font-medium hover:bg-brand-dark whitespace-nowrap">
                    Add account
                  </button>
                </form>

                {accounts.length > 0 ? (
                  <ul className="divide-y rounded-xl border overflow-hidden">
                    {accounts.map(a => (
                      <li key={a.id} className="flex items-center justify-between px-4 py-3 bg-white hover:bg-gray-50">
                        <div>
                          <span className="font-mono text-sm">{a.account_id}</span>
                          {a.account_name && <span className="ml-3 text-gray-400 text-sm">{a.account_name}</span>}
                        </div>
                        <button type="button" onClick={() => removeAccount(a.account_id)}
                          className="text-sm text-red-500 hover:text-red-700">Remove</button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="rounded-xl border border-dashed p-6 text-center text-sm text-gray-400">
                    No accounts added yet. Add your first account above.
                  </div>
                )}
              </>
            )}

            {(accounts.length > 0 || config.use_organizations) && (
              <div className="rounded-xl bg-green-50 border border-green-200 p-4 flex items-start gap-3">
                <span className="text-green-500 text-xl">✓</span>
                <div>
                  <p className="font-medium text-green-800 text-sm">Setup complete</p>
                  <p className="text-green-700 text-xs mt-0.5">
                    Your AWS environment is connected. Go to the Dashboard and click <strong>Run New Audit</strong> to get started.
                  </p>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <button type="button" onClick={() => setStep(2)}
                className="text-sm text-gray-500 hover:text-gray-800">← Back</button>
              <button type="button" onClick={() => router.push("/dashboard")}
                className="bg-brand text-white px-6 py-2 rounded-lg font-medium hover:bg-brand-dark">
                Go to Dashboard →
              </button>
            </div>
          </div>
        )}
      </main>

      <style jsx global>{`
        .input {
          width: 100%;
          border: 1px solid #d1d5db;
          border-radius: 0.5rem;
          padding: 0.5rem 0.75rem;
          font-size: 0.875rem;
          outline: none;
          background: white;
        }
        .input:focus {
          border-color: #2563eb;
          box-shadow: 0 0 0 2px #bfdbfe;
        }
      `}</style>
    </>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium">{label}</label>
      {hint && <p className="text-xs text-gray-400">{hint}</p>}
      {children}
    </div>
  );
}

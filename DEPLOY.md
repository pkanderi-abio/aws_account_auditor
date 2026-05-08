# Deploying to Streamlit Community Cloud

This guide walks you through deploying the AWS Security Auditor to [Streamlit Community Cloud](https://share.streamlit.io) (free tier).

## Prerequisites

- A GitHub account with this repo pushed to it
- A [Supabase](https://supabase.com) project (free tier works)
- Streamlit Community Cloud account (free, sign in with GitHub)

---

## Step 1 — Supabase setup

### Create tables

Run the following SQL in your Supabase project → SQL Editor:

```sql
-- AWS configurations per user
create table if not exists aws_configs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  deployer_role_arn text,
  deployer_external_id text,
  audit_role_name text default 'AuditRole',
  audit_role_external_id text,
  regions text[] default array['us-east-1'],
  use_organizations boolean default false,
  enabled_audits text[] default array[]::text[],
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  unique(user_id)
);

-- Target AWS accounts per user
create table if not exists aws_accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  account_id text not null,
  account_name text default '',
  created_at timestamptz default now()
);

-- Audit job records
create table if not exists audit_jobs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  status text default 'pending',
  accounts_audited text[] default array[]::text[],
  total_findings integer default 0,
  error_message text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz default now()
);

-- Individual findings
create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  job_id uuid references audit_jobs(id) on delete cascade not null,
  user_id uuid references auth.users(id) on delete cascade not null,
  account_id text,
  region text,
  service text,
  check_name text,
  status text,
  severity text,
  finding_type text,
  details text,
  recommendation text,
  timestamp timestamptz,
  compliance jsonb default '{}',
  ai_remediation jsonb,
  created_at timestamptz default now()
);

-- AI analysis results
create table if not exists ai_analyses (
  id uuid primary key default gen_random_uuid(),
  job_id uuid references audit_jobs(id) on delete cascade not null,
  user_id uuid references auth.users(id) on delete cascade not null,
  headline text,
  risk_level text,
  summary text,
  top_risks text[],
  quick_wins text[],
  narrative text,
  executive_report text,
  raw_response jsonb,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  unique(job_id)
);

-- Row Level Security (enable for each table)
alter table aws_configs  enable row level security;
alter table aws_accounts enable row level security;
alter table audit_jobs   enable row level security;
alter table findings     enable row level security;
alter table ai_analyses  enable row level security;

-- Policies — users see only their own data
create policy "own aws_configs"  on aws_configs  for all using (auth.uid() = user_id);
create policy "own aws_accounts" on aws_accounts for all using (auth.uid() = user_id);
create policy "own audit_jobs"   on audit_jobs   for all using (auth.uid() = user_id);
create policy "own findings"     on findings     for all using (auth.uid() = user_id);
create policy "own ai_analyses"  on ai_analyses  for all using (auth.uid() = user_id);
```

### Get your keys

In Supabase → Project Settings → API:
- **URL** — your project URL (`https://xxxx.supabase.co`)
- **anon/public key** — used for auth
- **service_role key** — used for server-side DB access (keep secret)

---

## Step 2 — GitHub repository

Make sure `secrets.toml` is **not** committed (it's in `.gitignore`). Push your code:

```bash
git add .
git commit -m "Add Streamlit deployment"
git push origin main
```

---

## Step 3 — Deploy on Streamlit Community Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub
2. Click **New app**
3. Fill in:
   - **Repository:** `your-github-username/aws_account_auditor`
   - **Branch:** `main`
   - **Main file path:** `streamlit_app/app.py`
4. Click **Advanced settings** → **Secrets** and paste:

```toml
[supabase]
url              = "https://xxxxxxxxxxxxxxxxxxxx.supabase.co"
anon_key         = "eyJ..."
service_role_key = "eyJ..."
```

5. Click **Deploy**

The app will be live at `https://your-app-name.streamlit.app`.

---

## Step 4 — AWS credentials for audit execution

The Streamlit app needs AWS credentials to assume the deployer role. On Streamlit Cloud, add these to **Secrets**:

```toml
[supabase]
url              = "https://xxxx.supabase.co"
anon_key         = "eyJ..."
service_role_key = "eyJ..."

# AWS credentials for the app to assume the deployer role
AWS_ACCESS_KEY_ID     = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
```

These are read as environment variables by `boto3` in `audit_runner.py`.

> **Tip:** Create a dedicated IAM user with only `sts:AssumeRole` permission on the deployer role ARN.

---

## Running locally

```bash
# Install deps
pip install -r streamlit_requirements.txt

# Copy and fill in secrets
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit .streamlit/secrets.toml with your Supabase keys

# Start the app
streamlit run streamlit_app/app.py
```

For AI features locally, also start Ollama:

```bash
ollama serve
ollama pull llama3.2
```

---

## AI features on Streamlit Cloud

AI analysis (Ollama) is **only available when running locally**. On Streamlit Cloud, the app gracefully degrades:
- All audit, findings, and compliance features work normally
- AI buttons show a "Start Ollama locally" message instead

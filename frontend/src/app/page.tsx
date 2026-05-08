"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabase";

const FEATURES = [
  {
    icon: "🔍",
    title: "Multi-Account Auditing",
    desc: "Audit every AWS account in your organization simultaneously — IAM, S3, EC2, RDS, EKS, and more.",
  },
  {
    icon: "⚡",
    title: "Concurrent Execution",
    desc: "All audit modules run in parallel across regions. A full org audit completes in minutes, not hours.",
  },
  {
    icon: "🛡️",
    title: "Security & Compliance",
    desc: "Checks mapped to CIS, PCI-DSS, and SOC 2 controls. Security Hub, GuardDuty, and CloudTrail integrated.",
  },
  {
    icon: "💰",
    title: "Cost Optimization",
    desc: "Surface idle resources, unattached volumes, and reservation opportunities alongside security findings.",
  },
  {
    icon: "🔐",
    title: "Zero Credential Storage",
    desc: "We never store your AWS credentials. Role-assumption via ExternalId keeps your data under your control.",
  },
  {
    icon: "📊",
    title: "Rich Reporting",
    desc: "Filter findings by severity, service, account, and region. Export to JSON, CSV, or view in-browser.",
  },
];

const STEPS = [
  {
    n: "1",
    title: "Create your account",
    desc: "Sign up with your work email. No credit card required to start.",
  },
  {
    n: "2",
    title: "Deploy the IAM roles",
    desc: "Run our CloudFormation template in your management account and StackSet across sub-accounts. Takes ~5 minutes.",
  },
  {
    n: "3",
    title: "Connect & audit",
    desc: "Paste the role ARN into Settings, add your accounts, and click Run Audit.",
  },
];

export default function LandingPage() {
  const router = useRouter();
  const [checkingAuth, setCheckingAuth] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) {
        router.replace("/dashboard");
      } else {
        setCheckingAuth(false);
      }
    });
  }, [router]);

  return (
    <div className="min-h-screen bg-white text-gray-900 flex flex-col">
      {/* ── Nav ── */}
      <header className="sticky top-0 z-30 bg-white/80 backdrop-blur border-b">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <span className="font-extrabold text-xl text-brand">AWS Auditor</span>
          <nav className="flex items-center gap-6">
            <a href="#features" className="text-sm text-gray-600 hover:text-gray-900 hidden sm:block">Features</a>
            <a href="#how-it-works" className="text-sm text-gray-600 hover:text-gray-900 hidden sm:block">How it works</a>
            <Link href="/auth/login" className="text-sm font-medium text-gray-700 hover:text-brand">Sign in</Link>
            <Link href="/auth/signup"
              className="text-sm font-semibold bg-brand text-white px-4 py-2 rounded-lg hover:bg-brand-dark transition-colors">
              Get started free
            </Link>
          </nav>
        </div>
      </header>

      {/* ── Hero ── */}
      <section className="flex-1 flex flex-col items-center justify-center text-center px-6 py-24 bg-gradient-to-b from-blue-50 to-white">
        <div className="inline-flex items-center gap-2 bg-blue-100 text-blue-700 text-xs font-semibold px-3 py-1 rounded-full mb-6">
          Multi-account · Multi-region · Real-time
        </div>
        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight max-w-3xl leading-tight">
          Security auditing for your entire AWS organization
        </h1>
        <p className="mt-6 text-lg text-gray-500 max-w-xl">
          Connect once, audit everywhere. Surface IAM misconfigurations, public exposures,
          compliance gaps, and cost waste across every account — in minutes.
        </p>
        <div className="mt-10 flex flex-col sm:flex-row gap-4 items-center">
          <Link href="/auth/signup"
            className="bg-brand text-white px-8 py-3 rounded-xl font-semibold text-lg hover:bg-brand-dark transition-colors shadow-md shadow-blue-200">
            Start free audit
          </Link>
          <Link href="/auth/login"
            className="text-brand font-semibold text-lg hover:underline">
            Sign in →
          </Link>
        </div>
        <p className="mt-4 text-xs text-gray-400">No credit card required &nbsp;·&nbsp; Deploy in 5 minutes</p>
      </section>

      {/* ── Stats bar ── */}
      <section className="bg-gray-900 text-white py-10">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 sm:grid-cols-4 gap-8 text-center">
          {[
            { stat: "7", label: "Audit modules" },
            { stat: "4", label: "US regions" },
            { stat: "50+", label: "Security checks" },
            { stat: "<5m", label: "Time to first results" },
          ].map(({ stat, label }) => (
            <div key={label}>
              <p className="text-3xl font-extrabold text-blue-400">{stat}</p>
              <p className="text-sm text-gray-400 mt-1">{label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Features ── */}
      <section id="features" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-3">Everything you need to stay secure</h2>
          <p className="text-center text-gray-500 mb-12">One tool for security, compliance, and cost across your whole AWS footprint.</p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map(f => (
              <div key={f.title} className="border rounded-2xl p-6 hover:shadow-md transition-shadow bg-white">
                <div className="text-3xl mb-3">{f.icon}</div>
                <h3 className="font-semibold text-lg mb-2">{f.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section id="how-it-works" className="py-20 px-6 bg-gray-50">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-3">Up and running in minutes</h2>
          <p className="text-center text-gray-500 mb-12">No agents, no VPCs, no ongoing maintenance. Just IAM roles.</p>
          <div className="grid sm:grid-cols-3 gap-8">
            {STEPS.map(s => (
              <div key={s.n} className="text-center">
                <div className="w-12 h-12 rounded-full bg-brand text-white text-xl font-bold flex items-center justify-center mx-auto mb-4">
                  {s.n}
                </div>
                <h3 className="font-semibold text-lg mb-2">{s.title}</h3>
                <p className="text-sm text-gray-500">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Security callout ── */}
      <section className="py-16 px-6 bg-white border-y">
        <div className="max-w-3xl mx-auto text-center space-y-3">
          <div className="text-4xl">🔒</div>
          <h2 className="text-2xl font-bold">Your credentials never leave your account</h2>
          <p className="text-gray-500">
            We use AWS's native cross-account role assumption with ExternalId protection.
            The auditor assumes a read-only role you control — no long-lived keys, no stored secrets.
            You can revoke access instantly by deleting the role.
          </p>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="py-20 px-6 bg-brand text-white text-center">
        <h2 className="text-3xl font-bold mb-3">Ready to audit your AWS environment?</h2>
        <p className="text-blue-100 mb-8">Create your account and run your first audit in under 10 minutes.</p>
        <Link href="/auth/signup"
          className="inline-block bg-white text-brand font-bold px-8 py-3 rounded-xl text-lg hover:bg-blue-50 transition-colors shadow-lg">
          Get started free
        </Link>
      </section>

      {/* ── Footer ── */}
      <footer className="bg-gray-900 text-gray-400 py-8 px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <span className="font-bold text-white">AWS Auditor</span>
          <div className="flex gap-6 text-sm">
            <Link href="/auth/login" className="hover:text-white">Sign in</Link>
            <Link href="/auth/signup" className="hover:text-white">Sign up</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

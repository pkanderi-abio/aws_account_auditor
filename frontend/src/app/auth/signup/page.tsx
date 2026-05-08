"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import Link from "next/link";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    // Create user via backend (admin API — auto-confirms email, no rate-limit)
    const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    const createResp = await fetch(`${apiUrl}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!createResp.ok) {
      const body = await createResp.json().catch(() => ({}));
      setError(body.detail ?? "Signup failed. Try again.");
      setLoading(false);
      return;
    }

    // User is auto-confirmed — sign in immediately
    const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    setLoading(false);
    if (signInError) { setError(signInError.message); return; }
    router.replace("/dashboard");
  }

  if (confirmed) return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-md text-center">
        <div className="text-4xl mb-4">📧</div>
        <h1 className="text-2xl font-bold mb-2">Check your email</h1>
        <p className="text-gray-500">We sent a confirmation link to <strong>{email}</strong>. Click it to activate your account.</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-md">
        <h1 className="text-2xl font-bold mb-2 text-center">Create your account</h1>
        <p className="text-gray-500 text-center mb-6">Start auditing your AWS environment</p>
        {error && <p className="mb-4 text-sm text-red-600 bg-red-50 rounded-lg p-3">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="block text-sm font-medium mb-1">Email</label>
            <input id="email" type="email" required value={email} onChange={e => setEmail(e.target.value)}
              className="w-full border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-brand" />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm font-medium mb-1">Password</label>
            <input id="password" type="password" required minLength={8} value={password} onChange={e => setPassword(e.target.value)}
              className="w-full border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-brand" />
          </div>
          <button type="submit" disabled={loading}
            className="w-full bg-brand text-white py-2 rounded-lg font-medium hover:bg-brand-dark disabled:opacity-50">
            {loading ? "Creating account…" : "Sign up"}
          </button>
        </form>
        <p className="mt-4 text-center text-sm text-gray-500">
          Already have an account?{" "}
          <Link href="/auth/login" className="text-brand font-medium hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}

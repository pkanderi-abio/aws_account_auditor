"use client";
export const dynamic = 'force-dynamic';
import { useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob, type ChatMessage } from "@/lib/api";
import { Nav } from "@/components/nav";

const SUGGESTED_QUESTIONS = [
  "What are the most critical findings I should fix first?",
  "Which accounts have the most security issues?",
  "Are there any publicly exposed resources?",
  "What IAM misconfigurations were found?",
  "How do I fix the failing CIS controls?",
  "Give me a remediation plan for High severity findings.",
];

export default function ChatPage() {
  const router       = useRouter();
  const params       = useSearchParams();
  const jobIdParam   = params.get("job") ?? "";

  const [jobs, setJobs]         = useState<AuditJob[]>([]);
  const [jobId, setJobId]       = useState(jobIdParam);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput]       = useState("");
  const [streaming, setStreaming] = useState(false);
  const [ollamaOk, setOllamaOk] = useState<boolean | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) router.replace("/auth/login");
    });
    api.listAudits().then(all => {
      const completed = all.filter(j => j.status === "completed");
      setJobs(completed);
      if (!jobId && completed.length > 0) setJobId(completed[0].id);
    });
    api.ollamaHealth().then(h => setOllamaOk(h.status === "ok" && h.model_available));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const selectedJob = jobs.find(j => j.id === jobId);

  async function send(text: string) {
    if (!text.trim() || !jobId || streaming) return;
    const userMsg: ChatMessage = { role: "user", content: text.trim() };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setStreaming(true);

    const assistantMsg: ChatMessage = { role: "assistant", content: "" };
    setMessages(prev => [...prev, assistantMsg]);

    try {
      const resp = await api.chatStream(jobId, text.trim(), messages);
      if (!resp.ok || !resp.body) throw new Error("Stream failed");

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const payload = line.slice(6);
          if (payload === "[DONE]") break;
          try {
            const { token } = JSON.parse(payload);
            setMessages(prev => {
              const copy = [...prev];
              copy[copy.length - 1] = { role: "assistant", content: copy[copy.length - 1].content + token };
              return copy;
            });
          } catch { /* ignore malformed */ }
        }
      }
    } catch (err) {
      setMessages(prev => {
        const copy = [...prev];
        copy[copy.length - 1] = { role: "assistant", content: "⚠ Failed to get a response. Make sure Ollama is running." };
        return copy;
      });
    }
    setStreaming(false);
    inputRef.current?.focus();
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send(input);
    }
  }

  function clearChat() {
    setMessages([]);
    inputRef.current?.focus();
  }

  return (
    <>
      <Nav />

      {/* Header */}
      <div className="bg-gradient-to-br from-[#0f172a] via-[#1e293b] to-[#0f172a] text-white">
        <div className="max-w-4xl mx-auto px-6 py-8">
          <div className="flex items-center gap-3 mb-1">
            <span className="text-3xl">🤖</span>
            <h1 className="text-3xl font-extrabold tracking-tight">AI Security Chat</h1>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Ask natural language questions about your AWS audit findings — powered by local Ollama.
          </p>

          {/* Job selector + Ollama status */}
          <div className="mt-6 flex flex-col sm:flex-row gap-3 items-start sm:items-center">
            <div className="flex-1">
              <label className="text-xs text-slate-400 font-semibold tracking-widest block mb-1.5">AUDIT TO CHAT ABOUT</label>
              <select
                title="Select audit job"
                value={jobId}
                onChange={e => { setJobId(e.target.value); clearChat(); }}
                className="w-full bg-slate-800 border border-slate-600 text-white text-sm rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-orange-400"
              >
                {jobs.length === 0 && <option value="">No completed audits</option>}
                {jobs.map(j => (
                  <option key={j.id} value={j.id}>
                    {new Date(j.created_at).toLocaleString()} · {j.accounts_audited?.length ?? 0} accounts · {j.total_findings} findings
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 text-sm mt-5 sm:mt-0">
              <span className={`w-2 h-2 rounded-full ${ollamaOk === null ? "bg-gray-400" : ollamaOk ? "bg-green-400" : "bg-red-400"}`} />
              <span className="text-slate-400">
                {ollamaOk === null ? "Checking Ollama…" : ollamaOk ? "Ollama ready" : "Ollama unavailable"}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-6 py-6 flex flex-col" style={{ height: "calc(100vh - 280px)" }}>
        {/* Messages area */}
        <div className="flex-1 overflow-y-auto space-y-4 pb-4">
          {messages.length === 0 && (
            <div className="space-y-4">
              {!ollamaOk && ollamaOk !== null && (
                <div className="bg-red-50 border border-red-200 rounded-2xl p-4 text-sm text-red-700">
                  <strong>Ollama is not running or the model is not available.</strong>
                  <p className="mt-1 text-red-600">Start Ollama with: <code className="bg-red-100 px-1 rounded">ollama serve</code> then pull a model: <code className="bg-red-100 px-1 rounded">ollama pull llama3.2</code></p>
                </div>
              )}
              <div className="bg-white rounded-2xl border shadow-sm p-6">
                <p className="text-sm font-semibold text-gray-700 mb-4">Suggested questions</p>
                <div className="grid sm:grid-cols-2 gap-2">
                  {SUGGESTED_QUESTIONS.map(q => (
                    <button key={q} type="button" onClick={() => send(q)} disabled={!jobId || streaming}
                      className="text-left text-sm text-gray-600 hover:text-brand bg-gray-50 hover:bg-blue-50 border hover:border-brand rounded-xl px-4 py-3 transition-colors disabled:opacity-40">
                      {q}
                    </button>
                  ))}
                </div>
              </div>
              {selectedJob && (
                <div className="text-center text-xs text-gray-400">
                  Chatting about audit from {new Date(selectedJob.created_at).toLocaleString()} · {selectedJob.total_findings} findings
                </div>
              )}
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "assistant" && (
                <div className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center text-white text-sm shrink-0 mt-0.5">🤖</div>
              )}
              <div className={`max-w-[75%] rounded-2xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                msg.role === "user"
                  ? "bg-brand text-white rounded-br-sm"
                  : "bg-white border shadow-sm text-gray-800 rounded-bl-sm"
              }`}>
                {msg.content || (streaming && i === messages.length - 1
                  ? <span className="inline-flex gap-1"><span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }} /><span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }} /><span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }} /></span>
                  : ""
                )}
              </div>
              {msg.role === "user" && (
                <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-gray-500 text-sm shrink-0 mt-0.5">👤</div>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input bar */}
        <div className="border-t pt-4">
          {messages.length > 0 && (
            <div className="flex justify-end mb-2">
              <button type="button" onClick={clearChat} className="text-xs text-gray-400 hover:text-gray-600">Clear chat</button>
            </div>
          )}
          <div className="flex gap-3 items-end bg-white border rounded-2xl shadow-sm px-4 py-3 focus-within:ring-2 focus-within:ring-brand focus-within:border-brand transition-all">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={jobId ? "Ask about your AWS findings… (Enter to send, Shift+Enter for newline)" : "Select an audit above to start chatting"}
              disabled={!jobId || streaming}
              rows={1}
              className="flex-1 resize-none outline-none text-sm text-gray-800 placeholder-gray-400 disabled:opacity-50 leading-relaxed"
              style={{ maxHeight: "120px" }}
            />
            <button type="button" onClick={() => send(input)} disabled={!input.trim() || !jobId || streaming}
              className="shrink-0 bg-brand hover:bg-brand-dark disabled:opacity-40 text-white rounded-xl px-4 py-2 text-sm font-semibold transition-colors">
              {streaming ? "…" : "Send"}
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-2 text-center">Responses generated locally by Ollama — no data leaves your machine.</p>
        </div>
      </div>
    </>
  );
}

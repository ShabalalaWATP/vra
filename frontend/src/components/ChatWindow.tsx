import { useState, useRef, useEffect, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import {
  MessageSquare,
  X,
  Maximize2,
  Minimize2,
  Send,
  Loader2,
  ChevronDown,
  Bot,
  User,
  Brain,
} from "lucide-react";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface ChatWindowProps {
  scanId: string;
  currentFile?: string;
  currentFileContent?: string;
  initialPrompt?: string;
  onPromptConsumed?: () => void;
}

type ChatState = "closed" | "compact" | "expanded";

export default function ChatWindow({
  scanId,
  currentFile,
  currentFileContent,
  initialPrompt,
  onPromptConsumed,
}: ChatWindowProps) {
  const [state, setState] = useState<ChatState>("closed");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const [sendTrigger, setSendTrigger] = useState(0);
  const messagesRef = useRef(messages);
  messagesRef.current = messages;

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Abort in-flight fetch on unmount to prevent leaked state updates
  useEffect(() => {
    return () => { abortRef.current?.abort(); };
  }, []);

  useEffect(() => {
    if (state !== "closed" && inputRef.current) {
      inputRef.current.focus();
    }
  }, [state]);

  // Handle "Explain this finding" / "Ask about file" prompts from outside
  const pendingPromptRef = useRef<string | null>(null);

  useEffect(() => {
    if (initialPrompt && !streaming) {
      if (state === "closed") setState("compact");
      onPromptConsumed?.();
      // Store prompt and trigger auto-send on next render
      pendingPromptRef.current = initialPrompt;
    }
  }, [initialPrompt]);

  // Auto-send the pending prompt once chat is open
  useEffect(() => {
    const prompt = pendingPromptRef.current;
    if (!prompt || streaming || state === "closed") return;
    pendingPromptRef.current = null;

    // Directly send — don't put it in the input box
    const userMsg: ChatMessage = { role: "user", content: prompt };
    const newMessages = [...messagesRef.current, userMsg];
    setMessages(newMessages);
    setInput("");
    setStreaming(true);

    const assistantMsg: ChatMessage = { role: "assistant", content: "" };
    setMessages([...newMessages, assistantMsg]);

    // Fire the actual API call
    (async () => {
      try {
        const ctrl = new AbortController();
        abortRef.current = ctrl;
        const resp = await fetch(`/api/scans/${scanId}/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
            currently_viewing_file: currentFile || null,
            file_content: currentFileContent?.slice(0, 6000) || null,
          }),
          signal: ctrl.signal,
        });

        if (!resp.ok) {
          const err = await resp.text();
          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = { role: "assistant", content: `Error: ${err}` };
            return updated;
          });
          setStreaming(false);
          return;
        }

        const reader = resp.body?.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        if (!reader) { setStreaming(false); return; }

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const dataStr = line.slice(6).trim();
            if (!dataStr) continue;
            try {
              const data = JSON.parse(dataStr);
              if (data.error) {
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = { role: "assistant", content: `Error: ${data.error}` };
                  return updated;
                });
                break;
              }
              if (data.content) {
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = {
                    role: "assistant",
                    content: updated[updated.length - 1].content + data.content,
                  };
                  return updated;
                });
              }
              if (data.done) break;
            } catch { /* skip malformed */ }
          }
        }
      } catch (e: any) {
        if (e.name !== "AbortError") {
          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = { role: "assistant", content: `Connection error: ${e.message}` };
            return updated;
          });
        }
      } finally {
        setStreaming(false);
        abortRef.current = null;
      }
    })();
  }, [state, streaming, sendTrigger]);

  const sendMessage = async () => {
    const trimmed = input.trim();
    if (!trimmed || streaming) return;

    const userMsg: ChatMessage = { role: "user", content: trimmed };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setStreaming(true);

    // Add empty assistant message for streaming
    const assistantMsg: ChatMessage = { role: "assistant", content: "" };
    setMessages([...newMessages, assistantMsg]);

    try {
      abortRef.current = new AbortController();
      const resp = await fetch(`/api/scans/${scanId}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
          currently_viewing_file: currentFile || null,
          file_content: currentFileContent?.slice(0, 6000) || null,
        }),
        signal: abortRef.current.signal,
      });

      if (!resp.ok) {
        const err = await resp.text();
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: `Error: ${err}`,
          };
          return updated;
        });
        setStreaming(false);
        return;
      }

      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      if (!reader) {
        setStreaming(false);
        return;
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const dataStr = line.slice(6).trim();
          if (!dataStr) continue;

          try {
            const data = JSON.parse(dataStr);
            if (data.error) {
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: "assistant",
                  content: `Error: ${data.error}`,
                };
                return updated;
              });
              break;
            }
            if (data.content) {
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: "assistant",
                  content: updated[updated.length - 1].content + data.content,
                };
                return updated;
              });
            }
            if (data.done) break;
          } catch {
            // skip malformed chunks
          }
        }
      }
    } catch (e: any) {
      if (e.name !== "AbortError") {
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: `Connection error: ${e.message}`,
          };
          return updated;
        });
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // Floating button when closed
  if (state === "closed") {
    return (
      <button
        onClick={() => setState("compact")}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2 px-5 py-3 rounded-full
          bg-accent-primary text-bg-primary font-semibold text-sm
          shadow-lg shadow-accent-primary/30 hover:shadow-accent-primary/50
          hover:scale-105 transition-all duration-200"
      >
        <MessageSquare className="w-5 h-5" />
        Ask AI
      </button>
    );
  }

  const isExpanded = state === "expanded";

  return (
    <div
      className={`fixed z-50 flex flex-col bg-[#0a0a12] border border-[#1a1a2e] shadow-2xl shadow-black/50 transition-all duration-300 ${
        isExpanded
          ? "inset-x-[15%] inset-y-[5%] rounded-2xl"
          : "bottom-6 right-6 w-[420px] h-[550px] rounded-2xl"
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a2e] shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-accent-primary/15 flex items-center justify-center">
            <Bot className="w-4 h-4 text-accent-primary" />
          </div>
          <div>
            <span className="text-sm font-semibold text-text-primary">Security Assistant</span>
            {currentFile && (
              <p className="text-[10px] text-text-muted truncate max-w-[200px]">
                Viewing: {currentFile.split("/").pop()}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setState(isExpanded ? "compact" : "expanded")}
            className="p-1.5 hover:bg-bg-hover rounded-lg transition-colors"
            title={isExpanded ? "Minimize" : "Expand"}
          >
            {isExpanded ? (
              <Minimize2 className="w-4 h-4 text-text-muted" />
            ) : (
              <Maximize2 className="w-4 h-4 text-text-muted" />
            )}
          </button>
          <button
            onClick={() => setState("closed")}
            className="p-1.5 hover:bg-bg-hover rounded-lg transition-colors"
            title="Close"
          >
            <X className="w-4 h-4 text-text-muted" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center gap-3 py-8">
            <div className="w-12 h-12 rounded-xl bg-accent-primary/10 flex items-center justify-center">
              <Brain className="w-6 h-6 text-accent-primary" />
            </div>
            <div>
              <p className="text-sm font-medium text-text-primary">Security Assistant</p>
              <p className="text-xs text-text-muted mt-1 max-w-[280px]">
                Ask about findings, architecture, code vulnerabilities, or remediation.
                {currentFile && " I can see the file you're currently viewing."}
              </p>
            </div>
            <div className="flex flex-wrap gap-2 mt-2 justify-center">
              {[
                "Summarize the top risks",
                "What's the risk score?",
                "Explain the SQL injection findings",
              ].map((q) => (
                <button
                  key={q}
                  onClick={() => {
                    pendingPromptRef.current = q;
                    // Trigger the auto-send effect via state change
                    setSendTrigger((n) => n + 1);
                  }}
                  className="text-[11px] px-3 py-1.5 rounded-full bg-bg-secondary text-text-muted
                    hover:text-text-secondary hover:bg-bg-hover transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex gap-2 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            {msg.role === "assistant" && (
              <div className="w-6 h-6 rounded-md bg-accent-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                <Bot className="w-3.5 h-3.5 text-accent-primary" />
              </div>
            )}
            <div
              className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-sm ${
                msg.role === "user"
                  ? "bg-accent-primary/15 text-text-primary"
                  : "bg-[#12121f] text-text-secondary"
              }`}
            >
              {msg.role === "assistant" ? (
                <AssistantMessage content={msg.content} streaming={streaming && i === messages.length - 1} />
              ) : (
                <p className="whitespace-pre-wrap">{msg.content}</p>
              )}
            </div>
            {msg.role === "user" && (
              <div className="w-6 h-6 rounded-md bg-bg-secondary flex items-center justify-center shrink-0 mt-0.5">
                <User className="w-3.5 h-3.5 text-text-muted" />
              </div>
            )}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="px-4 py-3 border-t border-[#1a1a2e] shrink-0">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about the scan results..."
            rows={1}
            className="flex-1 resize-none bg-[#12121f] border border-[#1a1a2e] rounded-xl px-3.5 py-2.5
              text-sm text-text-primary placeholder:text-text-muted
              focus:outline-none focus:border-accent-primary/40
              max-h-[120px] overflow-y-auto"
            style={{ minHeight: 40 }}
            onInput={(e) => {
              const target = e.target as HTMLTextAreaElement;
              target.style.height = "auto";
              target.style.height = Math.min(target.scrollHeight, 120) + "px";
            }}
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || streaming}
            className="p-2.5 rounded-xl bg-accent-primary text-bg-primary
              disabled:opacity-30 disabled:cursor-not-allowed
              hover:bg-accent-primary/90 transition-colors shrink-0"
          >
            {streaming ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Assistant message renderer with markdown + thinking blocks ── */

function AssistantMessage({ content, streaming }: { content: string; streaming: boolean }) {
  if (!content && streaming) {
    return (
      <div className="flex items-center gap-2 py-1">
        <Loader2 className="w-3.5 h-3.5 animate-spin text-accent-primary" />
        <span className="text-xs text-text-muted">Thinking...</span>
      </div>
    );
  }

  // Extract thinking blocks
  const thinkingMatch = content.match(/^<think(?:ing)?>([\s\S]*?)<\/think(?:ing)?>\s*/);
  let displayContent = content;
  let thinkingContent = "";

  if (thinkingMatch) {
    thinkingContent = thinkingMatch[1].trim();
    displayContent = content.slice(thinkingMatch[0].length);
  }

  return (
    <div className="space-y-2">
      {thinkingContent && (
        <details className="group">
          <summary className="flex items-center gap-1.5 cursor-pointer text-[11px] text-text-muted hover:text-text-secondary select-none">
            <ChevronDown className="w-3 h-3 transition-transform group-open:rotate-0 -rotate-90" />
            <Brain className="w-3 h-3" />
            Thinking
          </summary>
          <div className="mt-1 pl-5 text-[11px] text-text-muted/70 leading-relaxed max-h-[200px] overflow-y-auto">
            {thinkingContent}
          </div>
        </details>
      )}
      {displayContent && (
        <div className="prose prose-invert prose-sm max-w-none
          prose-p:my-1.5 prose-p:leading-relaxed
          prose-headings:text-text-primary prose-headings:font-semibold prose-headings:mt-3 prose-headings:mb-1
          prose-ul:my-1 prose-ol:my-1 prose-li:my-0
          prose-strong:text-text-primary
          prose-code:text-accent-primary prose-code:bg-[#1a1a2e] prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-code:before:content-none prose-code:after:content-none
          prose-pre:bg-[#0c0c14] prose-pre:border prose-pre:border-[#1a1a2e] prose-pre:rounded-lg prose-pre:my-2
          prose-a:text-accent-primary">
          <ReactMarkdown
            components={{
              pre: ({ children }) => <>{children}</>,
              code: ({ className, children }) => {
                const isBlock = className?.startsWith("language-");
                const code = String(children).replace(/\n$/, "");
                if (!isBlock) {
                  return <code className={className}>{children}</code>;
                }
                return (
                  <div className="relative group my-2">
                    <button
                      onClick={() => navigator.clipboard.writeText(code)}
                      className="absolute top-2 right-2 px-2 py-1 rounded text-[10px] bg-bg-hover text-text-muted
                        opacity-0 group-hover:opacity-100 transition-opacity hover:text-text-primary"
                    >
                      Copy
                    </button>
                    <pre className="bg-[#0c0c14] border border-[#1a1a2e] rounded-lg p-3 overflow-x-auto">
                      <code className={className}>{code}</code>
                    </pre>
                  </div>
                );
              },
            }}
          >{displayContent}</ReactMarkdown>
        </div>
      )}
      {streaming && displayContent && (
        <span className="inline-block w-2 h-4 bg-accent-primary/60 animate-pulse rounded-sm" />
      )}
    </div>
  );
}

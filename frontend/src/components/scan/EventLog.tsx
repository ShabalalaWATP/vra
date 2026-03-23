import { useEffect, useRef } from "react";
import type { WSEvent } from "@/types";

interface EventLogProps {
  events: WSEvent[];
  maxHeight?: string;
}

const LEVEL_STYLES: Record<string, string> = {
  debug: "text-text-muted",
  info: "text-text-secondary",
  warn: "text-accent-warning",
  error: "text-accent-danger",
};

export default function EventLog({
  events,
  maxHeight = "400px",
}: EventLogProps) {
  const endRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      if (isNearBottom) {
        endRef.current?.scrollIntoView({ behavior: "smooth" });
      }
    }
  }, [events.length]);

  const logEvents = events.filter((e) => e.type === "event");

  return (
    <div
      ref={containerRef}
      className="overflow-y-auto font-mono text-xs space-y-0.5"
      style={{ maxHeight }}
    >
      {logEvents.length === 0 && (
        <p className="text-text-muted italic py-2">Waiting for events...</p>
      )}
      {logEvents.map((event, i) => (
        <div
          key={i}
          className={`py-0.5 leading-relaxed ${
            LEVEL_STYLES[event.level || "info"]
          }`}
        >
          <span className="text-text-muted opacity-60">
            [{event.phase || "—"}]
          </span>{" "}
          {event.level === "error" && (
            <span className="text-accent-danger font-bold">ERR </span>
          )}
          {event.level === "warn" && (
            <span className="text-accent-warning font-bold">WARN </span>
          )}
          {event.message}
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

import { useEffect, useRef, useState, useCallback } from "react";
import type { WSEvent } from "@/types";

export function useWebSocket(scanId: string | undefined) {
  const [events, setEvents] = useState<WSEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [lastProgress, setLastProgress] = useState<WSEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const lastProgressRef = useRef<WSEvent | null>(null);
  const mountedRef = useRef(true);
  const lastEventMsg = useRef<string>("");  // Dedup consecutive identical messages

  // Keep ref in sync with state so the callback always reads current value
  const updateProgress = useCallback((event: WSEvent) => {
    lastProgressRef.current = event;
    setLastProgress(event);
  }, []);

  const connect = useCallback(() => {
    if (!scanId) return;
    // Prevent duplicate connections
    if (wsRef.current && wsRef.current.readyState <= WebSocket.OPEN) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scans/${scanId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      if (mountedRef.current) setConnected(true);
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setConnected(false);
      // Auto-reconnect after 2s unless scan is done — use ref for current value
      const status = lastProgressRef.current?.status;
      if (status !== "completed" && status !== "failed" && status !== "cancelled") {
        reconnectTimer.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, 2000);
      }
    };

    ws.onerror = () => {
      if (mountedRef.current) setConnected(false);
    };

    ws.onmessage = (msg) => {
      if (!mountedRef.current) return;
      try {
        const event: WSEvent = JSON.parse(msg.data);
        if (event.type === "progress") {
          updateProgress(event);
        }
        // Dedup: skip if identical to previous event message
        const eventKey = event.message || "";
        if (event.type === "event" && eventKey && eventKey === lastEventMsg.current) {
          return; // Skip duplicate
        }
        if (event.type === "event" && eventKey) {
          lastEventMsg.current = eventKey;
        }
        setEvents((prev) => [...prev.slice(-500), event]);
      } catch {
        // Ignore malformed messages
      }
    };
  }, [scanId, updateProgress]);

  useEffect(() => {
    setEvents([]);
    setConnected(false);
    setLastProgress(null);
    lastProgressRef.current = null;
    lastEventMsg.current = "";
  }, [scanId]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { events, connected, lastProgress };
}

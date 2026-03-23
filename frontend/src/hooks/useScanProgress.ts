import { useQuery } from "@tanstack/react-query";
import { useWebSocket } from "./useWebSocket";
import { api } from "@/api/client";
import type { Scan } from "@/types";

/**
 * Combined hook for scan progress — polls the scan status
 * and streams real-time events via WebSocket.
 */
export function useScanProgress(scanId: string | undefined) {
  // Poll scan record for status
  const scanQuery = useQuery<Scan>({
    queryKey: ["scan", scanId],
    queryFn: () => api.get(`/scans/${scanId}`),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "completed" || status === "failed" || status === "cancelled") {
        return false; // Stop polling
      }
      return 3000; // Poll every 3s while running
    },
  });

  // WebSocket for real-time events
  const ws = useWebSocket(scanId);

  return {
    scan: scanQuery.data,
    scanLoading: scanQuery.isLoading,
    refetchScan: scanQuery.refetch,
    events: ws.events,
    connected: ws.connected,
    lastProgress: ws.lastProgress,
    isRunning: scanQuery.data?.status === "running",
    isComplete: scanQuery.data?.status === "completed",
    isFailed: scanQuery.data?.status === "failed",
  };
}

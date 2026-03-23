import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";

/**
 * Convenience hooks for common API mutations.
 */

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; description?: string; repo_path: string }) =>
      api.post("/projects", data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete(`/projects/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (data: {
      project_id: string;
      llm_profile_id?: string;
      mode: string;
    }) => {
      const scan = await api.post<{ id: string }>("/scans", data);
      await api.post(`/scans/${scan.id}/start`);
      return scan;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.post(`/scans/${scanId}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useExportReport() {
  return useMutation({
    mutationFn: async ({
      scanId,
      format,
    }: {
      scanId: string;
      format: "pdf" | "docx";
    }) => {
      const result = await api.post<{ id: string }>(
        `/scans/${scanId}/report/export`,
        { format }
      );
      window.open(
        `/api/scans/${scanId}/report/export/${result.id}/download`,
        "_blank"
      );
      return result;
    },
  });
}

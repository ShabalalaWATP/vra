import { useState } from "react";
import { Download, FileText, Loader2 } from "lucide-react";
import { api } from "@/api/client";

interface ExportButtonsProps {
  scanId: string;
}

export default function ExportButtons({ scanId }: ExportButtonsProps) {
  const [exporting, setExporting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async (format: "pdf" | "docx") => {
    setExporting(format);
    setError(null);
    try {
      const result = await api.post<{ id: string }>(
        `/scans/${scanId}/report/export`,
        { format }
      );
      // Open download link
      window.open(
        `/api/scans/${scanId}/report/export/${result.id}/download`,
        "_blank"
      );
    } catch (e) {
      setError(`Export failed: ${(e as Error).message}`);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="flex items-center gap-3">
      <button
        className="btn-secondary flex items-center gap-2"
        onClick={() => handleExport("pdf")}
        disabled={exporting !== null}
      >
        {exporting === "pdf" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Download className="w-4 h-4" />
        )}
        Export PDF
      </button>
      <button
        className="btn-secondary flex items-center gap-2"
        onClick={() => handleExport("docx")}
        disabled={exporting !== null}
      >
        {exporting === "docx" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <FileText className="w-4 h-4" />
        )}
        Export DOCX
      </button>
      {error && (
        <span className="text-xs text-accent-danger">{error}</span>
      )}
    </div>
  );
}

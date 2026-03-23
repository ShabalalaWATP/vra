import { useState } from "react";
import { Maximize2, Minimize2 } from "lucide-react";

interface DiagramViewProps {
  scanId: string;
  diagramSpec?: string | null;
  hasDiagramImage: boolean;
}

export default function DiagramView({
  scanId,
  diagramSpec,
  hasDiagramImage,
}: DiagramViewProps) {
  const [expanded, setExpanded] = useState(false);
  const [showSource, setShowSource] = useState(false);

  if (!hasDiagramImage && !diagramSpec) {
    return null;
  }

  const imageUrl = `/api/scans/${scanId}/report/diagram`;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Architecture Diagram</h2>
        <div className="flex gap-2">
          {diagramSpec && (
            <button
              className="btn-secondary text-xs"
              onClick={() => setShowSource(!showSource)}
            >
              {showSource ? "Hide Source" : "View Source"}
            </button>
          )}
          <button
            className="btn-secondary text-xs flex items-center gap-1"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? (
              <>
                <Minimize2 className="w-3 h-3" /> Collapse
              </>
            ) : (
              <>
                <Maximize2 className="w-3 h-3" /> Expand
              </>
            )}
          </button>
        </div>
      </div>

      {/* Diagram Image */}
      {hasDiagramImage && (
        <div
          className={`bg-bg-secondary rounded-lg p-6 overflow-auto transition-all ${
            expanded ? "max-h-none" : "max-h-[500px]"
          }`}
        >
          <img
            src={imageUrl}
            alt="Architecture diagram"
            className="max-w-full mx-auto"
            style={{ minHeight: 200 }}
          />
        </div>
      )}

      {/* Mermaid Source */}
      {showSource && diagramSpec && (
        <div className="relative">
          <pre className="bg-bg-secondary rounded-lg p-4 text-xs font-mono text-text-secondary overflow-x-auto max-h-[300px] overflow-y-auto">
            {diagramSpec}
          </pre>
          <button
            className="absolute top-2 right-2 btn-secondary text-xs"
            onClick={() => navigator.clipboard.writeText(diagramSpec)}
          >
            Copy
          </button>
        </div>
      )}
    </div>
  );
}

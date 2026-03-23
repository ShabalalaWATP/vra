import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import type { Finding } from "@/types";
import CodeSnippet from "./CodeSnippet";

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export default function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      {/* Header */}
      <button
        className="w-full flex items-center gap-4 p-4 hover:bg-bg-hover/30 text-left transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-text-muted shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-text-muted shrink-0" />
        )}
        <span className="text-text-muted text-sm w-8">{index}.</span>
        <span className={`badge badge-${finding.severity} shrink-0`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className="font-medium flex-1">{finding.title}</span>
        <span className="text-sm text-text-muted shrink-0">
          {Math.round(finding.confidence * 100)}%
        </span>
        {finding.category && (
          <span className="text-xs text-text-muted bg-bg-secondary px-2 py-0.5 rounded shrink-0">
            {finding.category}
          </span>
        )}
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="px-6 pb-6 space-y-5 border-t border-border">
          {/* Description */}
          <div className="pt-4">
            <p className="text-sm text-text-secondary leading-relaxed">
              {finding.description}
            </p>
          </div>

          {/* Code */}
          {finding.code_snippet && (
            <div>
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Vulnerable Code
              </h4>
              <CodeSnippet
                code={finding.code_snippet}
                fileName={finding.file_paths[0]}
              />
            </div>
          )}

          {/* Explanation */}
          {finding.explanation && (
            <div>
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Explanation
              </h4>
              <p className="text-sm text-text-secondary leading-relaxed">
                {finding.explanation}
              </p>
            </div>
          )}

          {/* Impact */}
          {finding.impact && (
            <div>
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Impact
              </h4>
              <p className="text-sm text-text-secondary leading-relaxed">
                {finding.impact}
              </p>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div className="bg-accent-success/5 border border-accent-success/20 rounded-lg p-4">
              <h4 className="text-xs font-semibold text-accent-success uppercase tracking-wide mb-2">
                Remediation
              </h4>
              <p className="text-sm text-text-primary leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-2">
                Evidence
              </h4>
              <div className="space-y-2">
                {finding.evidence.map((ev) => (
                  <div
                    key={ev.id}
                    className={`text-sm flex items-start gap-2 ${
                      ev.type === "supporting"
                        ? "text-accent-danger"
                        : ev.type === "opposing"
                        ? "text-accent-success"
                        : "text-text-secondary"
                    }`}
                  >
                    <span className="shrink-0 mt-0.5">
                      {ev.type === "supporting"
                        ? "+"
                        : ev.type === "opposing"
                        ? "-"
                        : "~"}
                    </span>
                    <span>{ev.description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Affected Files */}
          {finding.file_paths.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {finding.file_paths.map((fp) => (
                <span
                  key={fp}
                  className="text-xs font-mono bg-bg-secondary px-2 py-1 rounded text-text-secondary"
                >
                  {fp}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

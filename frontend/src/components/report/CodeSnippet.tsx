interface CodeSnippetProps {
  code: string;
  language?: string;
  fileName?: string;
  startLine?: number;
  highlightLines?: number[];
}

export default function CodeSnippet({
  code,
  language,
  fileName,
  startLine = 1,
  highlightLines = [],
}: CodeSnippetProps) {
  const lines = code.split("\n");
  const highlightSet = new Set(highlightLines);

  return (
    <div className="rounded-lg overflow-hidden border border-border">
      {fileName && (
        <div className="bg-bg-tertiary px-4 py-2 border-b border-border flex items-center justify-between">
          <span className="text-xs font-mono text-text-secondary">
            {fileName}
          </span>
          {language && (
            <span className="text-xs text-text-muted badge badge-info">
              {language}
            </span>
          )}
        </div>
      )}
      <div className="bg-bg-secondary overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <tbody>
            {lines.map((line, i) => {
              const lineNum = startLine + i;
              const isHighlighted = highlightSet.has(lineNum);
              return (
                <tr
                  key={i}
                  className={
                    isHighlighted
                      ? "bg-accent-danger/10 border-l-2 border-accent-danger"
                      : "hover:bg-bg-hover/20"
                  }
                >
                  <td className="text-text-muted text-right pr-4 pl-4 py-0 select-none w-12 align-top">
                    {lineNum}
                  </td>
                  <td className="pr-4 py-0 whitespace-pre">
                    {line || " "}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

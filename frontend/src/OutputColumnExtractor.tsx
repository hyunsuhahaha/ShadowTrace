import { useMemo, useState } from "react";
import { api } from "./api";

const DELIMITERS: { label: string; value: string }[] = [
  { label: "공백", value: " " },
  { label: "쉼표(,)", value: "," },
  { label: "콜론(:)", value: ":" },
];

const PREVIEW_ROWS = 6;
const PREVIEW_LIMIT = 20;

const splitLine = (line: string, delimiter: string) =>
  line.split(delimiter).map((token) => token.trim()).filter(Boolean);

// One-record-per-line tool output (netexec, crackmapexec, enum4linux…) can be
// cut into columns the same way `tr -s ' ' | cut -d ' ' -f N-` does on the
// terminal. Free-form output (nmap scripts, banners) just won't have a
// column that lines up, so this stays an opt-in helper, not a parser.
export default function OutputColumnExtractor({ executionId, stdout, onSaved }: {
  executionId: number;
  stdout: string;
  onSaved?: (filePath: string) => void;
}) {
  const [delimiter, setDelimiter] = useState(" ");
  const [column, setColumn] = useState<number>();
  const [mode, setMode] = useState<"rest" | "exact">("rest");
  const [filename, setFilename] = useState("");
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [error, setError] = useState("");

  const lines = useMemo(
    () => stdout.split("\n").map((line) => line.trim()).filter(Boolean),
    [stdout],
  );
  const rows = useMemo(
    () => lines.map((line) => splitLine(line, delimiter)),
    [lines, delimiter],
  );
  const previewRows = rows.slice(0, PREVIEW_ROWS);
  const columnCount = previewRows.reduce((max, row) => Math.max(max, row.length), 0);
  const extracted = useMemo(() => {
    if (column == null) return [];
    return rows
      .filter((cols) => cols.length > column)
      .map((cols) => mode === "rest" ? cols.slice(column).join(delimiter) : cols[column]);
  }, [rows, column, mode, delimiter]);

  const pickDelimiter = (value: string) => {
    setDelimiter(value);
    setColumn(undefined);
    setSaveState("idle");
  };

  const save = async () => {
    if (!filename.trim() || !extracted.length) return;
    setSaveState("saving");
    setError("");
    try {
      const saved = await api<{ file_path: string }>(`/executions/${executionId}/derive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: extracted.join("\n"), filename: filename.trim() }),
      });
      setSaveState("saved");
      onSaved?.(saved.file_path);
    } catch (reason) {
      setSaveState("error");
      setError(String(reason).replace(/^Error:\s*/, ""));
    }
  };

  if (!lines.length) return null;

  return (
    <details className="outputExtract">
      <summary>속성만 뽑아서 저장</summary>
      <div className="outputExtract__delimiters" role="radiogroup" aria-label="구분자">
        {DELIMITERS.map((item) => (
          <button key={item.value} type="button"
            aria-pressed={delimiter === item.value}
            className={delimiter === item.value ? "active" : ""}
            onClick={() => pickDelimiter(item.value)}>
            {item.label}
          </button>
        ))}
      </div>
      <p className="outputExtract__hint">값을 클릭해 그 컬럼을 선택하세요.</p>
      <div className="outputExtract__preview">
        <table>
          <tbody>
            {previewRows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {Array.from({ length: columnCount }).map((_, colIndex) => (
                  <td key={colIndex}>
                    {row[colIndex] != null && (
                      <button type="button"
                        aria-pressed={column === colIndex}
                        className={column === colIndex ? "active" : ""}
                        onClick={() => { setColumn(colIndex); setSaveState("idle"); }}>
                        {row[colIndex]}
                      </button>
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {column != null && <>
        <label className="outputExtract__mode">
          <input type="checkbox" checked={mode === "rest"}
            onChange={(event) => {
              setMode(event.target.checked ? "rest" : "exact");
              setSaveState("idle");
            }} />
          선택한 컬럼부터 끝까지 포함
        </label>
        <p>추출된 값 {extracted.length}개</p>
        <pre>{extracted.slice(0, PREVIEW_LIMIT).join("\n")}
          {extracted.length > PREVIEW_LIMIT
            ? `\n… 외 ${extracted.length - PREVIEW_LIMIT}개` : ""}
        </pre>
        <div className="outputExtract__save">
          <input placeholder="저장할 파일 이름 (예: users)" value={filename}
            onChange={(event) => { setFilename(event.target.value); setSaveState("idle"); }} />
          <button type="button" disabled={!filename.trim() || saveState === "saving"}
            onClick={() => void save()}>
            {saveState === "saving" ? "저장 중…" : "파일 + Evidence로 저장"}
          </button>
        </div>
        {saveState === "saved" && <small className="outputExtract__ok">
          프로젝트 폴더에 파일로 저장하고 Evidence에 등록했습니다.
        </small>}
        {saveState === "error" && <em role="alert">{error}</em>}
      </>}
    </details>
  );
}

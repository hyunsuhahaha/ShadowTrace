import { useEffect, useState } from "react";
import { parseRecycleBinIndex } from "./recycleBinIndex";

// The Recycle Bin's $I<random> index file (paired with the deleted content
// itself in $R<random>) records the original path, size, and deletion time
// of anything sent there — worth checking whenever a foothold turns up a
// $RECYCLE.BIN folder with old $I/$R pairs, since recovering the $R file
// under its real name/extension is often all it takes to open it.
export default function RecycleBinDecoder() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ReturnType<typeof parseRecycleBinIndex>>();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const value = input.trim();
    if (!value) {
      setResult(undefined);
      setChecked(false);
      return;
    }
    setResult(parseRecycleBinIndex(value));
    setChecked(true);
  }, [input]);

  return (
    <section className="netexecCredCheck" aria-labelledby="recyclebin-heading">
      <header>
        <h2 id="recyclebin-heading">$RECYCLE.BIN 인덱스($I) 파싱</h2>
        <small>$I&lt;random&gt; 파일을 base64로 붙여넣으면 원본 경로·크기·삭제 시각을 확인합니다.
          같은 이름의 $R&lt;random&gt; 파일이 실제 삭제된 내용입니다 — 원본 확장자로 이름을
          바꿔 여세요. Windows 10 이상 형식만 지원합니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <textarea rows={3} value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="$I 파일 (base64)" aria-label="$I 파일 (base64)" />
      </div>
      {checked && (
        result
          ? <p className="netexecEvidenceMsg">
              원본 경로: <code>{result.originalPath}</code><br />
              크기: <code>{result.originalSize.toString()}</code> 바이트<br />
              삭제 시각: <code>{result.deletedAt.toISOString()}</code>
            </p>
          : <p role="alert">파싱 실패 — Windows 10 이상의 $I 파일이 맞는지 확인하세요.</p>
      )}
    </section>
  );
}

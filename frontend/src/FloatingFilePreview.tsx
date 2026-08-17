import {useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent} from "react";
import "./floating-file-preview.css";

type Frame = {x: number; y: number; width: number; height: number};
type Direction = "move" | "n" | "s" | "e" | "w" | "ne" | "nw" | "se" | "sw";
const MIN_WIDTH = 420;
const MIN_HEIGHT = 260;
const EDGE = 8;

const initialFrame = (): Frame => ({
  x: Math.min(80, Math.max(EDGE, innerWidth - 720)),
  y: 80,
  width: Math.min(820, innerWidth - EDGE * 2),
  height: Math.min(680, innerHeight - 96),
});

export default function FloatingFilePreview({path, previewUrl, downloadUrl, onClose}: {
  path: string; previewUrl: string; downloadUrl: string; onClose: () => void;
}) {
  const [frame, setFrame] = useState(initialFrame);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [mediaType, setMediaType] = useState("text/plain");
  const [content, setContent] = useState("");
  const [error, setError] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeMatch, setActiveMatch] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const drag = useRef<{direction: Direction; x: number; y: number; frame: Frame} | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState("loading"); setContent(""); setError("");
    fetch(previewUrl).then(async (response) => {
      if (!response.ok) throw new Error(response.statusText || "파일을 열지 못했습니다.");
      const type = response.headers.get("Content-Type")?.split(";")[0] || "application/octet-stream";
      if (cancelled) return;
      setMediaType(type);
      if (type.startsWith("text/") || /(?:json|xml|javascript|yaml|toml)/i.test(type))
        setContent(await response.text());
      setState("ready");
    }).catch((reason) => {
      if (cancelled) return;
      setError(reason instanceof Error ? reason.message : String(reason)); setState("error");
    });
    return () => { cancelled = true; };
  }, [previewUrl]);

  const matches = useMemo(() => {
    if (!query) return [];
    const found: number[] = [], source = content.toLocaleLowerCase();
    const needle = query.toLocaleLowerCase();
    for (let index = 0; (index = source.indexOf(needle, index)) >= 0; index += needle.length)
      found.push(index);
    return found;
  }, [content, query]);
  useEffect(() => setActiveMatch(0), [query]);
  useEffect(() => {
    if (!matches.length) return;
    const active = document.querySelector(".floatingFilePreview mark.is-active") as HTMLElement | null;
    active?.scrollIntoView?.({block: "center"});
  }, [activeMatch, matches.length]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault(); setSearchOpen(true); requestAnimationFrame(() => searchRef.current?.focus());
      } else if (event.key === "Escape") {
        if (searchOpen) { setSearchOpen(false); setQuery(""); } else onClose();
      } else if (event.key === "Enter" && searchOpen && matches.length) {
        event.preventDefault();
        setActiveMatch((current) => (current + (event.shiftKey ? -1 : 1) + matches.length) % matches.length);
      }
    };
    addEventListener("keydown", keydown);
    return () => removeEventListener("keydown", keydown);
  }, [matches.length, onClose, searchOpen]);

  useEffect(() => {
    const move = (event: PointerEvent) => {
      const start = drag.current;
      if (!start) return;
      const dx = event.clientX - start.x, dy = event.clientY - start.y;
      let left = start.frame.x, top = start.frame.y;
      let right = left + start.frame.width, bottom = top + start.frame.height;
      if (start.direction === "move") {
        left = Math.min(Math.max(EDGE, start.frame.x + dx), innerWidth - start.frame.width - EDGE);
        top = Math.min(Math.max(EDGE, start.frame.y + dy), innerHeight - start.frame.height - EDGE);
        right = left + start.frame.width; bottom = top + start.frame.height;
      } else {
        if (start.direction.includes("w")) left = Math.min(Math.max(EDGE, left + dx), right - MIN_WIDTH);
        if (start.direction.includes("e")) right = Math.max(Math.min(innerWidth - EDGE, right + dx), left + MIN_WIDTH);
        if (start.direction.includes("n")) top = Math.min(Math.max(EDGE, top + dy), bottom - MIN_HEIGHT);
        if (start.direction.includes("s")) bottom = Math.max(Math.min(innerHeight - EDGE, bottom + dy), top + MIN_HEIGHT);
      }
      setFrame({x: left, y: top, width: right - left, height: bottom - top});
    };
    const finish = () => { drag.current = null; };
    addEventListener("pointermove", move); addEventListener("pointerup", finish);
    addEventListener("pointercancel", finish);
    return () => {
      removeEventListener("pointermove", move); removeEventListener("pointerup", finish);
      removeEventListener("pointercancel", finish);
    };
  }, []);

  const begin = (direction: Direction) => (event: ReactPointerEvent) => {
    if (event.button !== 0 || (event.target as HTMLElement).closest("button,a,input")) return;
    drag.current = {direction, x: event.clientX, y: event.clientY, frame};
    event.preventDefault();
  };
  const find = (step: number) => matches.length &&
    setActiveMatch((current) => (current + step + matches.length) % matches.length);
  const textBody = (() => {
    if (!matches.length || !query) return content || "(빈 파일)";
    const parts: Array<string | JSX.Element> = [];
    let cursor = 0;
    matches.forEach((index, matchIndex) => {
      parts.push(content.slice(cursor, index));
      parts.push(<mark key={index} className={matchIndex === activeMatch ? "is-active" : ""}>
        {content.slice(index, index + query.length)}</mark>);
      cursor = index + query.length;
    });
    parts.push(content.slice(cursor));
    return parts;
  })();
  const isText = mediaType.startsWith("text/") || /(?:json|xml|javascript|yaml|toml)/i.test(mediaType);

  return <section className="floatingFilePreview" role="dialog"
      aria-label={`AutoRecon 파일 · ${path}`}
      style={{left: frame.x, top: frame.y, width: frame.width, height: frame.height}}>
    <header className="floatingFilePreview__bar" data-testid="file-preview-drag-handle"
      onPointerDown={begin("move")}>
      <span className="termDots" aria-hidden="true"><i className="termDot" />
        <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
      <div><small>AUTORECON FILE</small><strong>{path}</strong></div>
      <button type="button" title="검색 (Ctrl+F)" aria-label="검색"
        onClick={() => {setSearchOpen(true); requestAnimationFrame(() => searchRef.current?.focus());}}>⌕</button>
      <button type="button" title="닫기" aria-label="닫기" onClick={onClose}>×</button>
    </header>
    {searchOpen && <div className="floatingFilePreview__search">
      <input ref={searchRef} type="search" role="searchbox" aria-label="파일 내용 검색"
        value={query} onChange={(event) => setQuery(event.target.value)} placeholder="검색…" />
      <span>{query ? matches.length ? `${activeMatch + 1} / ${matches.length}` : "0 / 0" : ""}</span>
      <button type="button" title="이전 일치" onClick={() => find(-1)}>↑</button>
      <button type="button" title="다음 일치" onClick={() => find(1)}>↓</button>
      <button type="button" title="검색 닫기" onClick={() => {setSearchOpen(false); setQuery("");}}>×</button>
    </div>}
    <div className="floatingFilePreview__body">
      {state === "loading" && <p>파일을 불러오는 중…</p>}
      {state === "error" && <p className="is-error">{error}</p>}
      {state === "ready" && isText && <pre className="floatingFilePreview__text">{textBody}</pre>}
      {state === "ready" && mediaType.startsWith("image/") &&
        <img src={previewUrl} alt={path} />}
      {state === "ready" && !isText && !mediaType.startsWith("image/") &&
        <iframe title={path} sandbox="" src={previewUrl} />}
    </div>
    <footer><span>{mediaType}</span><a href={downloadUrl}>다운로드</a></footer>
    {(["n", "s", "e", "w", "ne", "nw", "se", "sw"] as Direction[]).map((direction) =>
      <i key={direction} className={`floatingFilePreview__resize is-${direction}`}
        data-resize-direction={direction} onPointerDown={begin(direction)} />)}
  </section>;
}

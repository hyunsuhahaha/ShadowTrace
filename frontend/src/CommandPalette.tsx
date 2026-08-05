import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { commandPaletteIndex, searchCommandPalette, type CommandPaletteEntry } from "./commandPaletteIndex";
import "./command-palette.css";

const recentKey = "oscp-command-palette-recent";
const maxRecent = 5;

const loadRecent = (): string[] => {
  try {
    const raw = JSON.parse(localStorage.getItem(recentKey) || "[]");
    return Array.isArray(raw) ? raw.filter((id) => typeof id === "string") : [];
  } catch {
    return [];
  }
};

const rememberRecent = (id: string) => {
  const next = [id, ...loadRecent().filter((existing) => existing !== id)].slice(0, maxRecent);
  localStorage.setItem(recentKey, JSON.stringify(next));
};

export default function CommandPalette({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setSelected(0);
  }, [query]);

  const groups = useMemo(() => {
    const trimmed = query.trim();
    const grouped = new Map<string, CommandPaletteEntry[]>();
    if (trimmed) {
      searchCommandPalette(trimmed).forEach((entry) => {
        grouped.set(entry.category, [...(grouped.get(entry.category) || []), entry]);
      });
    } else {
      const byId = new Map(commandPaletteIndex.map((entry) => [entry.id, entry]));
      const recent = loadRecent()
        .map((id) => byId.get(id))
        .filter((entry): entry is CommandPaletteEntry => !!entry);
      if (recent.length) grouped.set("최근 사용", recent);
    }
    return [...grouped.entries()];
  }, [query]);

  const flat = useMemo(() => groups.flatMap(([, entries]) => entries), [groups]);

  const activate = (entry: CommandPaletteEntry) => {
    rememberRecent(entry.id);
    location.hash = entry.subroute ? `${entry.route}/${entry.subroute}` : entry.route;
    if (entry.anchorId) {
      const anchorId = entry.anchorId;
      window.setTimeout(
        () => document.getElementById(anchorId)?.scrollIntoView({ behavior: "smooth", block: "start" }),
        300,
      );
    }
    onClose();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      onClose();
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelected((index) => Math.min(index + 1, flat.length - 1));
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelected((index) => Math.max(index - 1, 0));
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const entry = flat[selected];
      if (entry) activate(entry);
    }
  };

  return (
    <div className="modal commandPaletteOverlay" role="presentation" onClick={onClose}>
      <div
        className="commandPalette"
        role="dialog"
        aria-modal="true"
        aria-label="빠른 이동"
        onClick={(event) => event.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="도구나 화면 검색… (예: sql injection, repeater, 백업)"
          aria-label="빠른 이동 검색"
        />
        <div className="commandPaletteResults" role="listbox">
          {!flat.length && (
            <p className="commandPaletteEmpty">
              {query.trim() ? "일치하는 항목이 없습니다." : "최근 사용한 항목이 여기 표시됩니다."}
            </p>
          )}
          {groups.map(([category, entries]) => (
            <div key={category} className="commandPaletteGroup">
              <h3>{category}</h3>
              {entries.map((entry) => {
                const index = flat.indexOf(entry);
                return (
                  <button
                    key={entry.id}
                    type="button"
                    role="option"
                    aria-selected={index === selected}
                    className={index === selected ? "isActive" : ""}
                    onMouseEnter={() => setSelected(index)}
                    onClick={() => activate(entry)}
                  >
                    <strong>{entry.label}</strong>
                    <small>{entry.detail}</small>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

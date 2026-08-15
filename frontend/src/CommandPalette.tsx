import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  commandPaletteIndex, matchesServiceKind, searchCommandPalette,
  type CommandPaletteEntry, type ServiceSummary, type TargetSummary,
} from "./commandPaletteIndex";
import { setPendingServiceNav } from "./pendingServiceNav";
import { revealAnchor } from "./anchorUtils";
import "./command-palette.css";

type ServiceOption = { service: ServiceSummary; target?: TargetSummary };

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

export default function CommandPalette({
  onClose, services = [], targets = [],
}: {
  onClose: () => void;
  services?: ServiceSummary[];
  targets?: TargetSummary[];
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [missingAnchor, setMissingAnchor] = useState<string>();
  const [servicePicker, setServicePicker] = useState<
    { entry: CommandPaletteEntry; options: ServiceOption[] }
  >();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setSelected(0);
    setMissingAnchor(undefined);
    setServicePicker(undefined);
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
      // The Service Enumeration tools this covers (dir/vhost/param fuzz,
      // dns subdomain) only render once a matching service is selected for
      // the current target — closing unconditionally here used to look
      // like the click did nothing when that service isn't present yet.
      window.setTimeout(() => {
        const anchor = document.getElementById(anchorId);
        if (anchor) {
          revealAnchor(anchor);
          anchor.scrollIntoView({ behavior: "smooth", block: "start" });
          onClose();
          return;
        }
        const kind = entry.serviceKind;
        const options: ServiceOption[] = kind
          ? services
              .filter((service) => matchesServiceKind(service, kind))
              .map((service) => ({
                service,
                target: targets.find((target) => target.id === service.target_id),
              }))
          : [];
        if (options.length) setServicePicker({ entry, options });
        else setMissingAnchor(entry.label);
      }, 300);
      return;
    }
    onClose();
  };

  const chooseService = (entry: CommandPaletteEntry, option: ServiceOption) => {
    if (!option.target) return;
    setPendingServiceNav({
      targetId: option.target.id, serviceId: option.service.id, anchorId: entry.anchorId,
      projectId: Number(localStorage.getItem("oscp-workspace-project")),
    });
    location.hash = entry.route;
    dispatchEvent(new CustomEvent("oscp-service-nav"));
    setServicePicker(undefined);
    onClose();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      if (servicePicker) { setServicePicker(undefined); return; }
      onClose();
      return;
    }
    if (servicePicker) return;
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
        {servicePicker ? (
          <div className="commandPaletteServicePicker">
            <p className="commandPaletteMissing">
              현재 대상에는 없지만 '{servicePicker.entry.label}'을(를) 쓸 수 있는 서비스가 프로젝트에
              있습니다 · 이동할 서비스를 선택하세요
            </p>
            <div className="commandPaletteResults" role="listbox">
              <div className="commandPaletteGroup">
                {servicePicker.options.map(({ service, target }) => (
                  <button
                    key={service.id}
                    type="button"
                    role="option"
                    onClick={() => chooseService(servicePicker.entry, { service, target })}
                  >
                    <strong>{target ? `${target.name} · ${target.ip}` : `Target #${service.target_id}`}</strong>
                    <small>{service.port}/{service.protocol} · {service.product || service.name}</small>
                  </button>
                ))}
              </div>
            </div>
            <button
              type="button"
              className="commandPaletteBack"
              onClick={() => setServicePicker(undefined)}
            >
              ← 검색으로 돌아가기
            </button>
          </div>
        ) : (
          <>
            {missingAnchor && (
              <p className="commandPaletteMissing" role="alert">
                '{missingAnchor}'은(는) 지금 이 대상에 해당 서비스가 없어서 표시되지 않습니다.
              </p>
            )}
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
          </>
        )}
      </div>
    </div>
  );
}

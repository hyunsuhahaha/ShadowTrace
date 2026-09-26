import type {Service} from "./enumerationModel";

export default function ServiceList({
  services,
  selectedId,
  onSelect,
}: {
  services?: Service[];
  selectedId?: number;
  onSelect: (id: number) => void;
}) {
  return <>
    <div className="panelTitle">
      <span>서비스</span>
      <em>{services?.length || 0}개 열림</em>
    </div>
    {services?.map((service) => (
      <button
        className={service.id === selectedId ? "active" : ""}
        key={service.id}
        onClick={() => onSelect(service.id)}
      >
        <strong>{service.port}</strong>
        <span>
          {service.name.toUpperCase()}
          <small>
            {[service.product, service.version].filter(Boolean).join(" ") ||
              "제품·버전 미식별"}
          </small>
        </span>
        <i>{service.protocol}</i>
      </button>
    ))}
    {!services?.length && (
      <div className="empty">서비스 없음</div>
    )}
  </>;
}

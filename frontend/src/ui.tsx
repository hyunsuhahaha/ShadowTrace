import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

export const statusCopy: Record<string, string> = {
  all: "전체",
  queued: "대기 중",
  pending: "대기 중",
  starting: "실행 준비 중",
  running: "실행 중",
  processing: "결과 처리 중",
  completed: "완료",
  no_response: "응답 또는 식별 결과 없음",
  success: "완료",
  failed: "실패",
  error: "오류",
  stopped: "중단",
  interrupted: "비정상 중단",
  connected: "연결됨",
  disconnected: "연결 끊김",
  prepared: "검토됨 · 승인 대기",
  timed_out: "시간 초과",
  cancelled: "취소됨",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "quiet";
}) {
  return <button className={`uiButton uiButton--${variant} ${className}`} {...props} />;
}

export function Badge({ status, children }: { status?: string; children?: ReactNode }) {
  const value = status?.toLowerCase() || "neutral";
  return (
    <span className={`uiBadge uiBadge--${value}`}>
      <span aria-hidden="true" />
      {children || statusCopy[value] || status}
    </span>
  );
}

export function Card({ className = "", ...props }: HTMLAttributes<HTMLElement>) {
  return <section className={`uiCard ${className}`} {...props} />;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="uiPageHeader">
      <div>
        {eyebrow && <span># {eyebrow}</span>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="uiPageHeader__actions">{actions}</div>}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="uiState" role="status">
      <strong>{title}</strong>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function LoadingState({ label = "불러오는 중" }: { label?: string }) {
  return (
    <div className="uiState uiState--loading" role="status" aria-live="polite">
      <span className="uiSkeleton" aria-hidden="true" />
      <strong>{label}</strong>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="uiState uiState--error" role="alert">
      <strong>데이터를 불러오지 못했습니다</strong>
      <p>{message}</p>
    </div>
  );
}

import type {ReactNode} from "react";

export type OperatorFact = {
  label: string;
  value: ReactNode;
  tone?: "ready" | "warn" | "danger";
};

export default function OperatorContext({scope, prompt, comment, facts, actions}: {
  scope: string;
  prompt: string;
  comment?: string;
  facts: OperatorFact[];
  actions?: ReactNode;
}) {
  return <section className="operatorContext" aria-label={`${scope} 작업 컨텍스트`}>
    <header>
      <div>
        <small>{scope}</small>
        <strong>{prompt}</strong>
        {comment && <p># {comment}</p>}
      </div>
      {actions && <div className="operatorContext__actions">{actions}</div>}
    </header>
    <dl>{facts.map((fact) => <div key={fact.label} className={fact.tone ? `is-${fact.tone}` : ""}>
      <dt>{fact.label}</dt><dd>{fact.value}</dd>
    </div>)}</dl>
  </section>;
}

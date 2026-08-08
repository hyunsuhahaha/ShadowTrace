import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

// Local api helper mirrors App.tsx's until a shared client lands (roadmap P0).
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.status === 204 ? (null as T) : r.json();
};

export type StoredCredential = {
  id: number; target_id: number | null; username: string; domain: string;
  secret: string; has_secret: boolean; secret_hint: string;
  source_kind: string; source_detail: string;
};

export type CredentialStoreContext = {
  projectId?: number; targetId?: number; serviceId?: number;
  serviceName?: string;
};

// State + persistence for the "current credential I'm testing" identity plus
// the saved-credential list it draws from. Kept as a single hook because the
// form fields, apply(), save(), and delete() all mutate or read the same
// identity slice — splitting them would just spray the coupling across props.
export function useCredentialStore(ctx: CredentialStoreContext) {
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [hint, setHint] = useState("");
  const [storeSecret, setStoreSecret] = useState(false);
  const [sourceKind, setSourceKind] = useState("manual");
  const [sourceDetail, setSourceDetail] = useState("");
  const [saving, setSaving] = useState(false);

  const saved = useQuery({
    queryKey: ["credentials", ctx.projectId],
    queryFn: () => api<StoredCredential[]>(
      `/runbooks/credentials?project_id=${ctx.projectId}`),
    enabled: !!ctx.projectId,
  });

  const apply = (credential: StoredCredential) => {
    setDomain(credential.domain || "");
    setUsername(credential.username || "");
    // A stored secret auto-fills the live password so command generation and
    // re-validation work without re-typing; otherwise clear and re-enter.
    setPassword(credential.secret || "");
    setHint(credential.secret_hint || "");
    setSourceKind(credential.source_kind || "manual");
    setSourceDetail(credential.source_detail || "");
  };

  const save = async () => {
    if (!ctx.projectId || !username.trim()) return;
    setSaving(true);
    try {
      await api("/runbooks/credentials", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: ctx.projectId, target_id: ctx.targetId,
          service_id: ctx.serviceId,
          username, domain, secret_hint: hint,
          secret: storeSecret ? password : "",
          source_kind: sourceKind, source_detail: sourceDetail,
          service_names: ctx.serviceName ? [ctx.serviceName] : [],
        }),
      });
      await qc.invalidateQueries({ queryKey: ["credentials", ctx.projectId] });
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    await api(`/runbooks/credentials/${id}`, { method: "DELETE" });
    await qc.invalidateQueries({ queryKey: ["credentials", ctx.projectId] });
  };

  return {
    saved,
    domain, username, password, hint, storeSecret, sourceKind, sourceDetail,
    setDomain, setUsername, setPassword, setHint,
    setStoreSecret, setSourceKind, setSourceDetail,
    apply, save, remove, saving,
  };
}

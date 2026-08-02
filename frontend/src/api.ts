export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch("/api" + path, init);
  if (!response.ok)
    throw new Error((await response.json()).detail || response.statusText);
  return response.status === 204 ? (null as T) : response.json();
}

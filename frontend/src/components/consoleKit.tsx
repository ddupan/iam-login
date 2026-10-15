import { createContext, useCallback, useContext, useState, type MouseEvent, type ReactNode } from "react";

/** The access token was refused: the console signs in again. */
export class Expired extends Error { }
export class ApiError extends Error {
  constructor(readonly status: number) { super(String(status)); }
}

/** /api/iam with the console's bearer token; JSON in and out, 204 as null. */
export function bearerApi(token: string) {
  return async <T,>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await fetch(path, {
      method, cache: "no-store", redirect: "error",
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401) throw new Expired();
    if (!response.ok) throw new ApiError(response.status);
    return (response.status === 204 ? null : await response.json()) as T;
  };
}
export type Api = ReturnType<typeof bearerApi>;

/** Runs one request at a time; a failure becomes its HTTP status (0 when there was no answer). */
export function useAction(onExpired: () => void) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<number | null>(null);
  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true); setStatus(null);
    try { await action(); }
    catch (cause) { if (cause instanceof Expired) onExpired(); else setStatus(cause instanceof ApiError ? cause.status : 0); }
    finally { setBusy(false); }
  }, [onExpired]);
  return { busy, status, run };
}

/** Console views move between their own paths without reloading, which would sign in again. */
export const Navigate = createContext<(path: string) => void>(path => { window.location.assign(path); });

export function Link({ to, className, current, children }: { to: string; className?: string; current?: boolean; children: ReactNode }) {
  const navigate = useContext(Navigate);
  const click = (event: MouseEvent<HTMLAnchorElement>) => {
    // A new tab or window is a page load of its own.
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(to);
  };
  return <a href={to} className={className} aria-current={current ? "page" : undefined} onClick={click}>{children}</a>;
}

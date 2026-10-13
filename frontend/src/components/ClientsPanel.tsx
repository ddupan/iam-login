import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Trans, useTranslation } from "react-i18next";

type Client = {
  id: string; name: string; redirectUris: string[]; scopes: string[]; postLogoutRedirectUris: string[];
  loginEnabled: boolean; pkceRequired: boolean;
};
const blank: Client = { id: "", name: "", redirectUris: [], scopes: ["openid", "profile", "email", "groups"],
  postLogoutRedirectUris: [], loginEnabled: true, pkceRequired: true };
const STATUSES = ["400", "403", "404", "409"] as const;
type Problem = (typeof STATUSES)[number] | "unavailable" | "failed";
class Expired extends Error { }
class Failure extends Error {
  constructor(readonly problem: Problem) { super(problem); }
}

export function ClientsPanel({ token, onExpired }: { token: string; onExpired: () => void }) {
  const { t } = useTranslation();
  const [clients, setClients] = useState<Client[]>([]);
  const [editing, setEditing] = useState<{ client: Client; isNew: boolean } | null>(null);
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(null);
  const [error, setError] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);

  const api = useCallback(async (method: string, path: string, body?: unknown) => {
    const response = await fetch(path, {
      method, cache: "no-store", redirect: "error",
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401) throw new Expired();
    if (!response.ok) {
      const status = String(response.status);
      throw new Failure(STATUSES.find(known => known === status) ?? "unavailable");
    }
    return response.status === 204 ? null : response.json();
  }, [token]);

  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await action(); }
    catch (cause) { if (cause instanceof Expired) onExpired(); else setError(cause instanceof Failure ? cause.problem : "failed"); }
    finally { setBusy(false); }
  }, [onExpired]);

  // ponytail: first page only (the API pages before dropping unmanaged clients); add paging past 100 clients.
  const reload = useCallback(() => run(async () => setClients(await api("GET", "/api/iam/clients?page=0&size=100"))), [api, run]);
  useEffect(() => { reload(); }, [reload]);

  const save = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editing) return;
    const form = new FormData(event.currentTarget);
    const lines = (name: string) => String(form.get(name) ?? "").split("\n").map(line => line.trim()).filter(Boolean);
    const client: Client = {
      id: editing.isNew ? String(form.get("id")).trim() : editing.client.id,
      name: String(form.get("name")).trim(),
      redirectUris: lines("redirectUris"),
      scopes: [...new Set(["openid", ...String(form.get("scopes")).split(/\s+/).filter(Boolean)])],
      postLogoutRedirectUris: lines("postLogoutRedirectUris"),
      loginEnabled: form.get("loginEnabled") !== null,
      pkceRequired: form.get("pkceRequired") !== null,
    };
    run(async () => {
      if (editing.isNew) {
        const created = await api("POST", "/api/iam/clients", client);
        setSecret({ id: client.id, value: created.secret });
      } else {
        await api("PUT", `/api/iam/clients/${encodeURIComponent(client.id)}`, client);
      }
      setEditing(null);
      await reload();
    });
  };

  const rotate = (id: string) => {
    if (!window.confirm(t("clients.confirmRotate", { id }))) return;
    run(async () => setSecret({ id, value: (await api("POST", `/api/iam/clients/${encodeURIComponent(id)}/secret`)).secret }));
  };
  const remove = (id: string) => {
    if (!window.confirm(t("clients.confirmDelete", { id }))) return;
    run(async () => { await api("DELETE", `/api/iam/clients/${encodeURIComponent(id)}`); setEditing(null); await reload(); });
  };

  return <section className="card" aria-busy={busy}>
    {error && <p className="error" role="alert">{t(`clients.error.${error}`)}</p>}
    {secret && <div className="secret" role="status">
      <p><Trans i18nKey="clients.secretOnce" values={{ id: secret.id }} components={{ strong: <strong /> }} /></p>
      <output>{secret.value}</output>
      <button type="button" onClick={() => navigator.clipboard.writeText(secret.value)}>{t("clients.copy")}</button>
      <button type="button" onClick={() => setSecret(null)}>{t("clients.saved")}</button>
    </div>}
    {editing ? <form onSubmit={save}>
      <h1>{editing.isNew ? t("clients.new") : t("clients.editTitle", { id: editing.client.id })}</h1>
      {editing.isNew && <label>{t("clients.id")}<input name="id" required pattern="[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}" /></label>}
      <label>{t("clients.name")}<input name="name" required maxLength={200} defaultValue={editing.client.name} /></label>
      <label>{t("clients.redirectUris")}<textarea name="redirectUris" required rows={3} defaultValue={editing.client.redirectUris.join("\n")} /></label>
      <label>{t("clients.scopes")}<input name="scopes" required defaultValue={editing.client.scopes.join(" ")} /></label>
      <label>{t("clients.postLogoutRedirectUris")}<textarea name="postLogoutRedirectUris" rows={2} defaultValue={editing.client.postLogoutRedirectUris.join("\n")} /></label>
      <label className="inline"><input type="checkbox" name="loginEnabled" defaultChecked={editing.client.loginEnabled} />{t("clients.loginEnabled")}</label>
      <label className="inline"><input type="checkbox" name="pkceRequired" defaultChecked={editing.client.pkceRequired} />{t("clients.pkceRequired")}</label>
      <button className="primary" type="submit" disabled={busy}>{editing.isNew ? t("clients.create") : t("clients.save")}</button>
      <button type="button" onClick={() => setEditing(null)}>{t("clients.cancel")}</button>
    </form> : <>
      <h1>{t("clients.heading")}</h1>
      <button className="primary" type="button" onClick={() => setEditing({ client: blank, isNew: true })}>{t("clients.new")}</button>
      <table>
        <thead><tr><th>ID</th><th>{t("clients.name")}</th><th>{t("clients.status")}</th><th>{t("clients.actions")}</th></tr></thead>
        <tbody>{clients.map(client => <tr key={client.id}>
          <td>{client.id}</td><td>{client.name}</td><td>{client.loginEnabled ? t("clients.enabled") : t("clients.disabled")}</td>
          <td>
            <button type="button" onClick={() => setEditing({ client, isNew: false })}>{t("clients.edit")}</button>
            <button type="button" onClick={() => rotate(client.id)}>{t("clients.rotate")}</button>
            <button type="button" onClick={() => remove(client.id)}>{t("clients.delete")}</button>
          </td>
        </tr>)}</tbody>
      </table>
      {!clients.length && !busy && <p>{t("clients.empty")}</p>}
    </>}
  </section>;
}

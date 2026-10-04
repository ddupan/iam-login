import { useCallback, useEffect, useState, type FormEvent } from "react";

type Client = {
  id: string; name: string; redirectUris: string[]; scopes: string[]; postLogoutRedirectUris: string[];
  loginEnabled: boolean;
};
const blank: Client = { id: "", name: "", redirectUris: [], scopes: ["openid", "profile", "email", "groups"],
  postLogoutRedirectUris: [], loginEnabled: true };
const ERRORS: Record<number, string> = { 400: "输入无效：检查 ID、回调地址（HTTPS、无通配符）与 scope（须含 openid）。",
  403: "当前登录没有客户端管理权限。", 404: "客户端不存在。", 409: "冲突：ID 已存在，或该客户端不是本服务可管理的类型。" };
class Expired extends Error { }

export function ClientsPanel({ token, onExpired }: { token: string; onExpired: () => void }) {
  const [clients, setClients] = useState<Client[]>([]);
  const [editing, setEditing] = useState<{ client: Client; isNew: boolean } | null>(null);
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const api = useCallback(async (method: string, path: string, body?: unknown) => {
    const response = await fetch(path, {
      method, cache: "no-store", redirect: "error",
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401) throw new Expired();
    if (!response.ok) throw new Error(ERRORS[response.status] ?? "身份服务暂时不可用，请稍后重试。");
    return response.status === 204 ? null : response.json();
  }, [token]);

  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true); setError("");
    try { await action(); }
    catch (cause) { if (cause instanceof Expired) onExpired(); else setError(cause instanceof Error ? cause.message : "操作失败。"); }
    finally { setBusy(false); }
  }, [onExpired]);

  // ponytail: first page only (Hydra paginates before filtering); add paging when there are >100 clients.
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
    if (!window.confirm(`为 ${id} 生成新 secret？旧 secret 立即失效，应用需同步更新。`)) return;
    run(async () => setSecret({ id, value: (await api("POST", `/api/iam/clients/${encodeURIComponent(id)}/secret`)).secret }));
  };
  const remove = (id: string) => {
    if (!window.confirm(`删除客户端 ${id}？已签发的 token 与应用会话不会因此撤回。`)) return;
    run(async () => { await api("DELETE", `/api/iam/clients/${encodeURIComponent(id)}`); setEditing(null); await reload(); });
  };

  return <section className="card" aria-busy={busy}>
    {error && <p className="error" role="alert">{error}</p>}
    {secret && <div className="secret" role="status">
      <p><strong>{secret.id}</strong> 的 client secret 只显示这一次，请立即保存：</p>
      <output>{secret.value}</output>
      <button type="button" onClick={() => navigator.clipboard.writeText(secret.value)}>复制</button>
      <button type="button" onClick={() => setSecret(null)}>已保存，隐藏</button>
    </div>}
    {editing ? <form onSubmit={save}>
      <h1>{editing.isNew ? "新建客户端" : `编辑 ${editing.client.id}`}</h1>
      {editing.isNew && <label>Client ID<input name="id" required pattern="[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}" /></label>}
      <label>名称<input name="name" required maxLength={200} defaultValue={editing.client.name} /></label>
      <label>回调地址（每行一个）<textarea name="redirectUris" required rows={3} defaultValue={editing.client.redirectUris.join("\n")} /></label>
      <label>Scope（空格分隔，openid 必含；offline_access 会签发 refresh token）<input name="scopes" required
        defaultValue={editing.client.scopes.join(" ")} /></label>
      <label>注销后回跳地址（每行一个，可空）<textarea name="postLogoutRedirectUris" rows={2} defaultValue={editing.client.postLogoutRedirectUris.join("\n")} /></label>
      <label className="inline"><input type="checkbox" name="loginEnabled" defaultChecked={editing.client.loginEnabled} />允许登录</label>
      <button className="primary" type="submit" disabled={busy}>{editing.isNew ? "创建" : "保存"}</button>
      <button type="button" onClick={() => setEditing(null)}>取消</button>
    </form> : <>
      <h1>OIDC 客户端</h1>
      <button className="primary" type="button" onClick={() => setEditing({ client: blank, isNew: true })}>新建客户端</button>
      <table>
        <thead><tr><th>ID</th><th>名称</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>{clients.map(client => <tr key={client.id}>
          <td>{client.id}</td><td>{client.name}</td><td>{client.loginEnabled ? "启用" : "已禁用"}</td>
          <td>
            <button type="button" onClick={() => setEditing({ client, isNew: false })}>编辑</button>
            <button type="button" onClick={() => rotate(client.id)}>轮换 secret</button>
            <button type="button" onClick={() => remove(client.id)}>删除</button>
          </td>
        </tr>)}</tbody>
      </table>
      {!clients.length && !busy && <p>暂无可管理的客户端。</p>}
    </>}
  </section>;
}

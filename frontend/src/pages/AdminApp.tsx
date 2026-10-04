import { useEffect, useState } from "react";
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import { ClientsPanel } from "../components/ClientsPanel";
import type { AdminContext } from "../page-context";

/** Ordinary OIDC public client of this server; it holds no privileges beyond the access token it is granted. */
export function AdminApp({ context }: { context: AdminContext }) {
  const [manager] = useState(() => new UserManager({
    authority: context.authority,
    client_id: context.clientId,
    redirect_uri: `${window.location.origin}/console/callback`,
    // groups carries the identity facts the API authorizes on; its audience is registered with this client.
    scope: "openid groups",
    // Tokens stay in memory: a reload signs in again rather than leaving a bearer token in storage.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: false,
    monitorSession: false,
    loadUserInfo: false,
  }));
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (window.location.pathname !== "/console/callback") {
      manager.signinRedirect().catch(() => setError("无法连接统一登录，请稍后重试。"));
      return;
    }
    manager.signinRedirectCallback().then(signedIn => {
      window.history.replaceState(null, "", "/console");
      setUser(signedIn);
    }).catch(() => setError("登录未完成。需要管理组成员通过密码与 passkey 登录。"));
  }, [manager]);

  const signIn = () => { setError(""); manager.signinRedirect().catch(() => setError("无法连接统一登录，请稍后重试。")); };

  return <main className="admin">
    <header><a href="/console" className="brand">i<span>am</span></a> <span className="eyebrow">OIDC 客户端管理</span></header>
    {error && <section className="card"><p className="error" role="alert">{error}</p>
      <button type="button" className="primary" onClick={signIn}>重新登录</button></section>}
    {!error && !user && <p role="status">正在跳转统一登录…</p>}
    {user && <ClientsPanel token={user.access_token} onExpired={() => { setUser(null); setError("登录已过期，请重新登录。"); }} />}
  </main>;
}

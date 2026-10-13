import { useEffect, useState } from "react";
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import { useTranslation } from "react-i18next";
import { ClientsPanel } from "../components/ClientsPanel";
import type { AdminContext } from "../page-context";

type Problem = "" | "unreachable" | "incomplete" | "expired";

/** Ordinary OIDC public client of this server; it holds no privileges beyond the access token it is granted. */
export function AdminApp({ context }: { context: AdminContext }) {
  const { t } = useTranslation();
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
  const [error, setError] = useState<Problem>("");

  useEffect(() => {
    if (window.location.pathname !== "/console/callback") {
      manager.signinRedirect().catch(() => setError("unreachable"));
      return;
    }
    manager.signinRedirectCallback().then(signedIn => {
      window.history.replaceState(null, "", "/console");
      setUser(signedIn);
    }).catch(() => setError("incomplete"));
  }, [manager]);

  const signIn = () => { setError(""); manager.signinRedirect().catch(() => setError("unreachable")); };

  return <main className="admin">
    <header><a href="/console" className="brand">i<span>am</span></a> <span className="eyebrow">{t("admin.eyebrow")}</span></header>
    {error && <section className="card"><p className="error" role="alert">{t(`admin.error.${error}`)}</p>
      <button type="button" className="primary" onClick={signIn}>{t("admin.signInAgain")}</button></section>}
    {!error && !user && <p role="status">{t("admin.redirecting")}</p>}
    {user && <ClientsPanel token={user.access_token} onExpired={() => { setUser(null); setError("expired"); }} />}
  </main>;
}

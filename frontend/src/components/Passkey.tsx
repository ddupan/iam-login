import { useState } from "react";
import type { CsrfToken } from "../page-context";

export function Passkey({ csrf, initial }: { csrf: CsrfToken; initial: "register" | "authenticate" }) {
  const [step, setStep] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [registered, setRegistered] = useState(false);

  async function post(path: string, body?: unknown) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin", redirect: "error",
      headers: { "Content-Type": "application/json", [csrf.headerName]: csrf.value },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) {
      throw new Error("验证未完成，请重试；若登录已过期，请退出并重新验证密码。");
    }
    return response.json();
  }

  async function perform() {
    setBusy(true);
    setError("");
    try {
      if (!PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
        throw new Error("请使用支持 passkey 的新版浏览器。");
      }
      if (step === "register") {
        const options = await post("/webauthn/register/options");
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        }) as PublicKeyCredential | null;
        if (!credential) throw new Error("注册已取消。");
        await post("/webauthn/register", { publicKey: { credential: credential.toJSON(), label: "Passkey" } });
        setRegistered(true);
        setStep("authenticate");
      } else {
        const options = await post("/webauthn/authenticate/options");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        }) as PublicKeyCredential | null;
        if (!credential) throw new Error("验证已取消。");
        await post("/login/webauthn", credential.toJSON());
        window.location.assign("/signin/complete");
      }
    } catch (cause) {
      setError(cause instanceof DOMException ? "操作已取消或认证器不可用，可以重试。"
        : cause instanceof Error ? cause.message : "验证未完成，请重试。");
    } finally {
      setBusy(false);
    }
  }

  return <div className="passkey">
    {registered && <p role="status">Passkey 已保存，请验证一次以完成第二因素。</p>}
    {step === "register" && <p>首次使用，请注册 passkey。后续登录仍需 AD 密码和 passkey。</p>}
    {error && <p className="error" role="alert">{error}</p>}
    <button type="button" disabled={busy} onClick={perform}>
      {busy ? "等待认证器…" : step === "register" ? "注册 Passkey" : "验证 Passkey"}
    </button>
  </div>;
}

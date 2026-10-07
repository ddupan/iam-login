import { useState } from "react";
import type { CsrfToken } from "../page-context";
import { Alert } from "./Chrome";

/** Registers (first time) or verifies a passkey; the server owns every factor decision. */
export function Passkey({ csrf, initial, who }: { csrf: CsrfToken; initial: "register" | "authenticate"; who: string }) {
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
      throw new Error("验证已过期，请换一个账号重新登录。");
    }
    return response.json();
  }

  async function perform() {
    setBusy(true);
    setError("");
    try {
      if (!PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
        throw new Error("这个浏览器不支持 passkey，请换用新版浏览器。");
      }
      if (step === "register") {
        const options = await post("/webauthn/register/options");
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        }) as PublicKeyCredential | null;
        if (!credential) throw new Error("已取消。");
        await post("/webauthn/register", { publicKey: { credential: credential.toJSON(), label: "Passkey" } });
        setRegistered(true);
        setStep("authenticate");
      } else {
        const options = await post("/webauthn/authenticate/options");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        }) as PublicKeyCredential | null;
        if (!credential) throw new Error("已取消。");
        // Spring Security answers with the request that was interrupted for login (it consumes the saved
        // request); "/" means there was none, and the sign-in result page decides what comes next.
        const result = await post("/login/webauthn", credential.toJSON());
        const target = typeof result.redirectUrl === "string" ? new URL(result.redirectUrl, window.location.origin) : null;
        window.location.assign(target && target.origin === window.location.origin && target.pathname !== "/"
          ? target.toString() : "/signin/complete");
      }
    } catch (cause) {
      setError(cause instanceof DOMException ? "passkey 验证已取消或超时。"
        : cause instanceof Error ? cause.message : "验证未完成，请重试。");
    } finally {
      setBusy(false);
    }
  }

  if (step === "register") {
    return <>
      <div className="lead-block">
        <h1>创建 passkey</h1>
        <p className="lead">这个账号还没有 passkey。以后每次登录都需要它：存在本机、手机或安全密钥上，使用时要求 PIN 或生物识别。</p>
      </div>
      <div className="who"><span className="avatar" aria-hidden="true">{who.slice(0, 1).toUpperCase()}</span>
        <div><span>{who}</span><span>刚刚通过密码验证</span></div></div>
      {error && <Alert>{error}</Alert>}
      <button className="primary" type="button" disabled={busy} onClick={perform}>{busy ? "等待验证器…" : "创建 passkey"}</button>
    </>;
  }
  return <>
    <div className="centered">
      <div className="badge-icon" aria-hidden="true">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 11c0 3-1 6-3 8" /><path d="M8 7a5 5 0 0 1 9 3c0 2 0 4-1 6" /><path d="M5 10a7 7 0 0 1 2-5" /><path d="M12 11c0 2 .5 4 1.5 6" />
        </svg>
      </div>
      <h1>{registered ? "passkey 已创建" : "用 passkey 验证"}</h1>
      <p className="lead">{registered ? "用它验证一次即可继续。" : "按浏览器提示，用 PIN、指纹或安全密钥确认。"}</p>
    </div>
    {error && <Alert>{error}</Alert>}
    {busy && <p className="status" role="status">正在等待验证器…</p>}
    <button className="primary" type="button" disabled={busy} onClick={perform}>{error ? "重试" : "用 passkey 验证"}</button>
  </>;
}

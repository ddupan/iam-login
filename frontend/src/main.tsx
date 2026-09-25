import { createRoot } from "react-dom/client";
import { useState, useLayoutEffect, type ReactNode } from "react";
import "./style.css";

type PageContext = {
  step: "identity" | "verification" | "complete" | "password" | "mfa-pending";
  identity?: { username: string; objectGuid: string; email: string; groups: string[]; groupDns: string[] };
  name: string;
  error: string;
  action: string;
  csrf: { name: string; value: string };
};

const context: PageContext = JSON.parse(
  document.getElementById("login-context")!.textContent!,
);

function Form({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState(false);
  return (
    <form
      method="post"
      action={context.action}
      onSubmit={() => setPending(true)}
      aria-busy={pending}
    >
      <input
        type="hidden"
        name={context.csrf.name}
        value={context.csrf.value}
      />
      {children}
      <button className="primary" type="submit" disabled={pending}>
        {pending
          ? "正在继续…"
          : (context.step === "complete" || context.step === "mfa-pending")
            ? (context.step === "mfa-pending" ? "退出并重新验证" : "重新体验")
            : "继续"}
      </button>
    </form>
  );
}

function App() {
  useLayoutEffect(() => { performance.mark("iam-page-ready"); }, []);
  const [showHelp, setShowHelp] = useState(false);
  return (
    <main>
      <header>
        <a href="/preview" className="brand" aria-label="IAM 登录体验预览">
          i<span>am</span>
          <span className="badge">预览</span>
        </a>
      </header>
      <section className="card" aria-labelledby="title">
        <div className="eyebrow">登录交互原型</div>
        <ol className="steps" aria-label="当前步骤">
          {(["identity", "verification", "complete"] as const).map(
            (step, i) => (
              <li
                key={step}
                aria-current={context.step === step ? "step" : undefined}
              >
                <span>{i + 1}</span>
                {["填写称呼", "模拟验证", "完成"][i]}
              </li>
            ),
          )}
        </ol>
        {context.step === "identity" && (
          <>
            <h1 id="title">从这里开始</h1>
            <p className="intro">
              体验一次完整的页面切换。先告诉我们怎么称呼你。
            </p>
          </>
        )}
        {context.step === "verification" && (
          <>
            <h1 id="title">你好，{context.name}</h1>
            <p className="intro">
              这是第二步页面。输入演示码 <strong>123456</strong>{" "}
              继续，也可以试试输入错误的演示码。
            </p>
          </>
        )}
        {context.step === "complete" && (
          <>
            <div className="success" aria-hidden="true">
              ✓
            </div>
            <h1 id="title">体验完成</h1>
            <p className="intro">
              {context.name}
              ，你已走完页面预览。这没有建立登录身份，也没有向任何应用授权。
            </p>
          </>
        )}
        {context.error && (
          <p className="error" role="alert">
            {context.error}
          </p>
        )}
        <Form>
          {context.step === "identity" && (
            <label>
              称呼
              <input
                name="name"
                autoComplete="off"
                autoFocus
                required
                maxLength={64}
                placeholder="例如：小潘"
                defaultValue={context.name}
              />
            </label>
          )}
          {context.step === "verification" && (
            <label>
              演示码
              <input
                name="code"
                inputMode="numeric"
                autoComplete="off"
                autoFocus
                required
                maxLength={6}
                pattern="[0-9]{6}"
                placeholder="123456"
                aria-invalid={Boolean(context.error)}
              />
            </label>
          )}
        </Form>
        {context.step === "verification" && (
          <a className="back" href="/preview">
            返回上一步
          </a>
        )}
        <div className="help">
          <button
            type="button"
            className="link"
            aria-expanded={showHelp}
            onClick={() => setShowHelp(!showHelp)}
          >
            这是真实登录吗？
          </button>
          {showHelp && (
            <p>不是。这里仅演示页面交互，请勿输入真实密码或 MFA 验证码。</p>
          )}
        </div>
      </section>
      <footer>独立 IAM · 页面体验预览</footer>
    </main>
  );
}

function SignIn() {
  useLayoutEffect(() => { performance.mark("iam-page-ready"); }, []);
  const identity = context.identity;
  return <main>
    <header><a href="/signin" className="brand">i<span>am</span></a></header>
    <section className="card" aria-labelledby="title">
      <div className="eyebrow">AD 登录验证</div>
      <h1 id="title">{context.step === "password" ? "登录你的账号" : "密码已验证，等待 MFA"}</h1>
      <p className="intro">{context.step === "password"
        ? "使用 AD 用户名或完整 UPN 登录。"
        : `${context.name}，目录验证成功。第二因素尚未接入，本次没有完成登录或向应用授权。`}</p>
      {context.error && <p className="error" role="alert">{context.error}</p>}
      {identity && <div className="directory-result">
        <dl><dt>账号</dt><dd>{identity.username}</dd>
          <dt>目录标识</dt><dd>{identity.objectGuid}</dd>
          <dt>邮箱</dt><dd>{identity.email || "未设置"}</dd></dl>
        <h2>直接所属组</h2>
        {identity.groups.length ? <ul>{identity.groups.map(group => <li key={group}>{group}</li>)}</ul> : <p>没有直接所属组。</p>}
        <details><summary>组 DN</summary><ul>{identity.groupDns.map(dn => <li key={dn}>{dn}</li>)}</ul></details>
        <p>当前仅读取 memberOf，不展开嵌套组，也不包含主组。</p>
      </div>}
      <Form>{context.step === "password" && <>
        <label>用户名<input name="username" autoComplete="username" autoFocus required maxLength={256} defaultValue={context.name} /></label>
        <label>密码<input name="password" type="password" autoComplete="current-password" required maxLength={1024} /></label>
      </>}</Form>
    </section>
    <footer>独立 IAM · AD 接入验证</footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(
  context.step === "password" || context.step === "mfa-pending" ? <SignIn /> : <App />,
);

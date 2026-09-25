import { createRoot } from "react-dom/client";
import { useState, useLayoutEffect, type ReactNode } from "react";
import "./style.css";

type PageContext = {
  step: "identity" | "verification" | "complete";
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
          : context.step === "complete"
            ? "重新体验"
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

createRoot(document.getElementById("root")!).render(<App />);

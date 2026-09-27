import { useState, type ReactNode } from "react";
import type { CsrfToken } from "../page-context";

type Props = {
  action: string;
  csrf: CsrfToken;
  label: string;
  children?: ReactNode;
};

/** Submit a browser document request; the server owns authentication transitions. */
export function SubmitForm({ action, csrf, label, children }: Props) {
  const [pending, setPending] = useState(false);
  return (
    <form method="post" action={action} onSubmit={() => setPending(true)} aria-busy={pending}>
      <input type="hidden" name={csrf.name} value={csrf.value} />
      {children}
      <button className="primary" type="submit" disabled={pending}>
        {pending ? "正在继续…" : label}
      </button>
    </form>
  );
}

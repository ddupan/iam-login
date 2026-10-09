import { useState, type ReactNode } from "react";
import type { CsrfToken } from "../page-context";

type Props = {
  action: string;
  csrf: CsrfToken;
  label: string;
  className?: string;
  children?: ReactNode;
};

/** Submit a browser document request; the server owns authentication transitions. */
export function SubmitForm({ action, csrf, label, className = "primary", children }: Props) {
  const [pending, setPending] = useState(false);
  return (
    <form method="post" action={action} onSubmit={() => setPending(true)} aria-busy={pending}>
      <input type="hidden" name={csrf.name} value={csrf.value} />
      {children}
      <button className={className} type="submit" disabled={pending}>{label}</button>
    </form>
  );
}

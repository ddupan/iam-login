export type CsrfToken = { name: string; value: string };

type PageBase = {
  name: string;
  error: string;
  action: string;
  csrf: CsrfToken;
};

export type SignInContext = PageBase & (
  | { step: "password" }
  | {
      step: "mfa-pending";
      identity: {
        username: string;
        subjectId: string;
        email: string;
        groups: string[];
        groupDns: string[];
      };
    }
);

export function readPageContext(): SignInContext {
  const data = document.getElementById("login-context")?.textContent;
  if (!data) throw new Error("Missing login page context");
  const context: SignInContext = JSON.parse(data);
  if (context.step !== "password" && context.step !== "mfa-pending") {
    throw new Error("Unknown login step");
  }
  return context;
}

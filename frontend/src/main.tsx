import { createRoot } from "react-dom/client";
import { readPageContext } from "./page-context";
import { SignInPage } from "./pages/SignInPage";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <SignInPage context={readPageContext()} />,
);

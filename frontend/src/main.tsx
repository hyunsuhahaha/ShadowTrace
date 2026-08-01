import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./styles.css";
import "./scan.css";
import "./scan-enhanced.css";
import "./execution.css";
import "./enumeration-enhanced.css";
import "./web.css";
import "./web-enhanced.css";
import "./evidence.css";
import "./directory.css";
import "./sessions.css";
import "./reports.css";
import "./operations.css";
import "./exploit-research.css";
import "./runbooks.css";
import Root from "./Root";
createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={new QueryClient()}>
    <Root />
  </QueryClientProvider>,
);

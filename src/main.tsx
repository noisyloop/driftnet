import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("driftnet: #root mount point missing");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

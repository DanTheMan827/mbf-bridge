import type { ComponentType } from "preact";
import TestPage from "./pages/TestPage";
import ShiftPage from "./pages/ShiftPage";
import HelpPage from "./pages/HelpPage";
import WingetProgressPage from "./pages/WingetProgressPage";

const routes: Record<string, ComponentType> = {
  "/test": TestPage,
  "/shift": ShiftPage,
  "/help": HelpPage,
  "/winget-progress": WingetProgressPage,
};

export default function App() {
  const Page = routes[window.location.pathname] ?? TestPage;
  return <Page />;
}

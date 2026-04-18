import type { ComponentType } from "preact";
import ShiftPage from "./pages/ShiftPage";
import HelpPage from "./pages/HelpPage";
import WingetProgressPage from "./pages/WingetProgressPage";

const routes: Record<string, ComponentType> = {
  "/shift": ShiftPage,
  "/help": HelpPage,
  "/winget-progress": WingetProgressPage,
};

if (__DEV__) {
  const TestPage = await import("./pages/TestPage");
  routes["/test"] = TestPage.default;
}

export default function App() {
  const Page = routes[window.location.pathname] ?? HelpPage;
  return <Page />;
}

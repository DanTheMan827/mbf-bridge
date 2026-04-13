import { Routes, Route, Navigate } from "react-router-dom";
import TestPage from "./pages/TestPage";
import ShiftPage from "./pages/ShiftPage";
import HelpPage from "./pages/HelpPage";

export default function App() {
  return (
    <Routes>
      <Route path="/test" element={<TestPage />} />
      <Route path="/shift" element={<ShiftPage />} />
      <Route path="/help" element={<HelpPage />} />
      {/* Default to the test page for any unmatched path. */}
      <Route path="*" element={<Navigate to="/test" replace />} />
    </Routes>
  );
}

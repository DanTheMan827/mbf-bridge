import { Routes, Route, Navigate } from "react-router-dom";
import TestPage from "./pages/TestPage";
import ShiftPage from "./pages/ShiftPage";

export default function App() {
  return (
    <Routes>
      <Route path="/test" element={<TestPage />} />
      <Route path="/shift" element={<ShiftPage />} />
      {/* Default to the test page for any unmatched path. */}
      <Route path="*" element={<Navigate to="/test" replace />} />
    </Routes>
  );
}

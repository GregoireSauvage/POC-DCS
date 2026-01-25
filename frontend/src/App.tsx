import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Nav from "./components/Nav";
import RequireAuth from "./components/RequireAuth";

import Home from "./pages/Home";
import LoginAs from "./pages/LoginAs";
import Films from "./pages/Films";
import Halls from "./pages/Halls";
import Spectators from "./pages/Spectators";
import Audit from "./pages/Audit";
import Performance from "./pages/Performance";

export default function App() {
  return (
    <>
      <Nav />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<LoginAs />} />
        <Route path="/films" element={<RequireAuth><Films /></RequireAuth>} />
        <Route path="/halls" element={<RequireAuth><Halls /></RequireAuth>} />
        <Route path="/spectators" element={<RequireAuth><Spectators /></RequireAuth>} />
        <Route path="/audit" element={<RequireAuth><Audit /></RequireAuth>} />
        <Route path="/perf" element={<RequireAuth><Performance /></RequireAuth>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}

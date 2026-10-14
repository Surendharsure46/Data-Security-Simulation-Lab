import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { Layout } from "./components/Layout";
import { LevelGate } from "./components/toolAccess";
import { Card, Empty, ErrorBanner, Loading, ToastProvider } from "./components/ui";
import Admin from "./pages/Admin";
import AiLab from "./pages/AiLab";
import Assessment from "./pages/Assessment";
import Classification from "./pages/Classification";
import CloudLab from "./pages/CloudLab";
import Dashboard from "./pages/Dashboard";
import DatabaseLab from "./pages/DatabaseLab";
import Discovery from "./pages/Discovery";
import EncryptionLab from "./pages/EncryptionLab";
import Engineering from "./pages/Engineering";
import Events from "./pages/Events";
import Investigation from "./pages/Investigation";
import Journey from "./pages/journey/Journey";
import { LearnStep, LevelCheck, LevelPage } from "./pages/journey/Level";
import Learning from "./pages/Learning";
import Login from "./pages/Login";
import Mission, { CurrentMission } from "./pages/Mission";
import Policies from "./pages/Policies";
import PrivacyLab from "./pages/PrivacyLab";
import GetStarted, { takePendingRole } from "./pages/public/GetStarted";
import Welcome from "./pages/public/Welcome";
import RealTools from "./pages/RealTools";
import Workspace from "./pages/Workspace";
import { AuthProvider, CareerProvider, SessionProvider, useAuth, useCareer } from "./state";
import type { CareerProfile } from "./types";

// Signed in: the role chosen on the get-started page (before the account existed) is applied first.
function Workplace() {
  const { profile, loading, error, setProfile } = useCareer();
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  useEffect(() => {
    if (!profile || profile.onboarding_complete) return;
    const role = takePendingRole();
    if (!role) return;
    setApplying(true);
    api.put<CareerProfile>("/api/career/role", { role })
      .then(setProfile)
      .catch((e) => setApplyError(e instanceof Error ? e.message : String(e)))
      .finally(() => setApplying(false));
  }, [profile, setProfile]);
  if (loading || applying) return <div className="auth-wrap"><Loading label="Preparing your journey…" /></div>;
  if (!profile) return <div className="auth-wrap"><ErrorBanner error={error ?? applyError ?? "Could not load your profile"} /></div>;
  if (!profile.onboarding_complete) return <GetStarted signedIn />;
  return (
    <SessionProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Journey />} />
          <Route path="/levels/:level" element={<LevelPage />} />
          <Route path="/levels/:level/learn/:key" element={<LearnStep />} />
          <Route path="/levels/:level/check" element={<LevelCheck />} />
          <Route path="/mission" element={<CurrentMission />} />
          <Route path="/missions/:attemptId" element={<Mission />} />
          <Route path="/progress" element={<Dashboard />} />
          <Route path="/learning" element={<Learning />} />
          <Route path="/workspace" element={<LevelGate path="/workspace"><Workspace /></LevelGate>} />
          <Route path="/discovery" element={<LevelGate path="/discovery"><Discovery /></LevelGate>} />
          <Route path="/classification" element={<LevelGate path="/classification"><Classification /></LevelGate>} />
          <Route path="/policies" element={<LevelGate path="/policies"><Policies /></LevelGate>} />
          <Route path="/events" element={<LevelGate path="/events"><Events /></LevelGate>} />
          <Route path="/investigation" element={<LevelGate path="/investigation"><Investigation /></LevelGate>} />
          <Route path="/engineering" element={<LevelGate path="/engineering"><Engineering /></LevelGate>} />
          <Route path="/labs/encryption" element={<LevelGate path="/labs/encryption"><EncryptionLab /></LevelGate>} />
          <Route path="/labs/database" element={<LevelGate path="/labs/database"><DatabaseLab /></LevelGate>} />
          <Route path="/labs/privacy" element={<LevelGate path="/labs/privacy"><PrivacyLab /></LevelGate>} />
          <Route path="/labs/cloud" element={<LevelGate path="/labs/cloud"><CloudLab /></LevelGate>} />
          <Route path="/labs/ai" element={<LevelGate path="/labs/ai"><AiLab /></LevelGate>} />
          <Route path="/real-tools" element={<LevelGate path="/real-tools"><RealTools /></LevelGate>} />
          <Route path="/assessment" element={<Assessment />} />
          <Route path="/admin" element={<LevelGate path="/admin"><Admin /></LevelGate>} />
          <Route path="/get-started" element={<Navigate to="/" replace />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<Card><Empty title="Page not found"><p>Use the navigation to choose an area.</p></Empty></Card>} />
        </Routes>
      </Layout>
    </SessionProvider>
  );
}

function Shell() {
  const { user, loading } = useAuth();
  if (loading) return <div className="auth-wrap"><Loading label="Restoring session…" /></div>;
  if (!user) {
    // Public journey: Welcome -> Let's Get Started (platform + role) -> create account / sign in.
    return (
      <Routes>
        <Route path="/" element={<Welcome />} />
        <Route path="/get-started" element={<GetStarted />} />
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    );
  }
  return (
    <CareerProvider>
      <Workplace />
    </CareerProvider>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </ToastProvider>
  );
}

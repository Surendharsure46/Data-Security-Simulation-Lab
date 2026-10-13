import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Card, Empty, Loading, ToastProvider } from "./components/ui";
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
import Learning from "./pages/Learning";
import Login from "./pages/Login";
import Policies from "./pages/Policies";
import PrivacyLab from "./pages/PrivacyLab";
import RealTools from "./pages/RealTools";
import Workspace from "./pages/Workspace";
import { AuthProvider, SessionProvider, useAuth } from "./state";

function Shell() {
  const { user, loading } = useAuth();
  if (loading) return <div className="auth-wrap"><Loading label="Restoring session…" /></div>;
  if (!user) return <Login />;
  return (
    <SessionProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/learning" element={<Learning />} />
          <Route path="/workspace" element={<Workspace />} />
          <Route path="/discovery" element={<Discovery />} />
          <Route path="/classification" element={<Classification />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/events" element={<Events />} />
          <Route path="/investigation" element={<Investigation />} />
          <Route path="/engineering" element={<Engineering />} />
          <Route path="/labs/encryption" element={<EncryptionLab />} />
          <Route path="/labs/database" element={<DatabaseLab />} />
          <Route path="/labs/privacy" element={<PrivacyLab />} />
          <Route path="/labs/cloud" element={<CloudLab />} />
          <Route path="/labs/ai" element={<AiLab />} />
          <Route path="/real-tools" element={<RealTools />} />
          <Route path="/assessment" element={<Assessment />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="*" element={<Card><Empty title="Page not found"><p>Use the navigation to choose an area.</p></Empty></Card>} />
        </Routes>
      </Layout>
    </SessionProvider>
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

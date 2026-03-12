import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import Dashboard from "./pages/Dashboard";
import ServerDetail from "./pages/ServerDetail";
import DiffViewer from "./pages/DiffViewer";
import NotificationConfig from "./pages/NotificationConfig";

function Nav() {
  return (
    <nav className="bg-white border-b border-gray-200 sticky top-0 z-40">
      <div className="max-w-6xl mx-auto px-4 h-12 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 group">
          <img src="/logo.svg" alt="Vigil" className="h-7 w-7 rounded-lg" />
          <span className="font-bold text-gray-900 tracking-tight group-hover:text-blue-600 transition-colors">
            Vigil
          </span>
        </Link>
        <Link
          to="/notifications"
          className="text-sm text-gray-500 hover:text-blue-600 transition-colors"
        >
          Notifications
        </Link>
      </div>
    </nav>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Nav />
      <main className="min-h-screen bg-gray-50">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/servers/:id" element={<ServerDetail />} />
          <Route path="/servers/:id/diff/:diffId" element={<DiffViewer />} />
          <Route path="/notifications" element={<NotificationConfig />} />
        </Routes>
      </main>
      <Toaster position="bottom-right" />
    </BrowserRouter>
  );
}

import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import ServerDetail from "./pages/ServerDetail";
import DiffViewer from "./pages/DiffViewer";
import NotificationConfig from "./pages/NotificationConfig";
import SslMonitor from "./pages/SslMonitor";
import SslTargetDetail from "./pages/SslTargetDetail";

function Sidebar() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    [
      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
      isActive
        ? "bg-blue-50 text-blue-700"
        : "text-gray-600 hover:bg-gray-100 hover:text-gray-900",
    ].join(" ");

  return (
    <aside className="fixed top-0 left-0 h-screen w-56 bg-white border-r border-gray-200 flex flex-col z-40">
      {/* Logo */}
      <div className="px-4 h-14 flex items-center gap-2 border-b border-gray-200">
        <img src="/logo.svg" alt="Vigil" className="h-7 w-7 rounded-lg" />
        <span className="font-bold text-gray-900 tracking-tight">Vigil</span>
      </div>

      {/* Nav links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <NavLink to="/" end className={linkClass}>
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
          </svg>
          Home
        </NavLink>

        <NavLink to="/http" className={linkClass}>
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          HTTP Monitor
        </NavLink>

        <NavLink to="/ssl" className={linkClass}>
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          SSL Monitor
        </NavLink>

        <NavLink to="/notifications" className={linkClass}>
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          Notifications
        </NavLink>
      </nav>
    </aside>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-gray-50">
        <Sidebar />
        <main className="flex-1 ml-56 min-h-screen">
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/http" element={<Dashboard />} />
            <Route path="/http/servers/:id" element={<ServerDetail />} />
            <Route path="/http/servers/:id/diff/:diffId" element={<DiffViewer />} />
            <Route path="/ssl" element={<SslMonitor />} />
            <Route path="/ssl/:id" element={<SslTargetDetail />} />
            <Route path="/notifications" element={<NotificationConfig />} />
          </Routes>
        </main>
      </div>
      <Toaster position="bottom-right" />
    </BrowserRouter>
  );
}

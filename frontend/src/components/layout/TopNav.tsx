import { NavLink, Link } from "react-router-dom";
import {
  Home,
  ScanSearch,
  History,
  Settings,
  WifiOff,
} from "lucide-react";

const navItems = [
  { to: "/", icon: Home, label: "Home" },
  { to: "/scan/new", icon: ScanSearch, label: "New Scan" },
  { to: "/history", icon: History, label: "History" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function TopNav() {
  return (
    <header className="sticky top-0 z-50 border-b border-border/30 backdrop-blur-2xl bg-bg-primary/90 shadow-lg shadow-black/10">
      <div className="px-6 flex items-center h-[72px]">
        {/* Logo + Title — far left */}
        <Link to="/" className="flex items-center gap-3 shrink-0">
          <img
            src="/logo.png"
            alt="VRAgent"
            className="w-10 h-10 object-contain"
          />
          <span className="text-lg font-bold tracking-tight text-gradient">
            VRAgent
          </span>
        </Link>

        {/* Nav Links — centered */}
        <nav className="flex-1 flex items-center justify-center gap-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "bg-accent-primary/10 text-accent-primary"
                    : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                }`
              }
            >
              <item.icon className="w-4 h-4" />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Right side — air-gapped badge */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-accent-success/70">
            <WifiOff className="w-3 h-3" />
            AIR-GAPPED
          </div>
          <span className="text-[10px] font-mono text-text-muted/40">v0.1.0</span>
        </div>
      </div>
    </header>
  );
}

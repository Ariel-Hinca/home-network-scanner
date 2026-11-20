import { NavLink, Outlet } from "react-router-dom";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  [
    "rounded-full px-4 py-1.5 text-sm font-medium",
    isActive ? "bg-teal-800 text-white shadow-sm" : "text-stone-700 hover:bg-white",
  ].join(" ");

export function Layout() {
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-10 border-b border-teal-900/10 bg-white/80 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-2xl bg-teal-800 text-sm font-semibold text-white shadow-sm">
              HG
            </span>
            <div>
              <p className="text-lg font-semibold tracking-tight text-stone-900">HomeGuard</p>
              <p className="text-sm text-stone-600">See what is on your home Wi-Fi</p>
            </div>
          </div>
          <nav className="flex gap-1 rounded-full bg-stone-100 p-1" aria-label="Primary">
            <NavLink to="/" end className={linkClass}>
              Home
            </NavLink>
            <NavLink to="/setup" className={linkClass}>
              Setup
            </NavLink>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}

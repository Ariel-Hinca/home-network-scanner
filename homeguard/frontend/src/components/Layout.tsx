import { NavLink, Outlet } from "react-router-dom";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  [
    "rounded-md px-3 py-1.5 text-sm",
    isActive ? "bg-stone-900 text-stone-50" : "text-stone-700 hover:bg-stone-200",
  ].join(" ");

export function Layout() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-300 bg-stone-100">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-6 py-4">
          <div>
            <p className="text-lg font-medium tracking-tight">HomeGuard</p>
            <p className="text-sm text-stone-600">See what is on your home Wi-Fi</p>
          </div>
          <nav className="flex gap-2" aria-label="Primary">
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

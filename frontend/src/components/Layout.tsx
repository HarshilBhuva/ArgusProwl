import { NavLink } from 'react-router-dom';
import { cn } from '../lib/utils';
import Logo from '../assets/argusprowl_owl_logo_same_style.svg';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/alerts', label: 'Alerts', end: false },
  { to: '/incidents', label: 'Incidents', end: false },
  { to: '/entities', label: 'Entities', end: false },
  { to: '/rules', label: 'Rules', end: false },
  { to: '/iocs', label: 'IOCs', end: false },
  { to: '/attck', label: 'ATT&CK', end: false },
];

function NavItems({ className }: { className?: string }) {
  return (
    <nav aria-label="Primary" className={className}>
      {NAV_ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            cn(
              'rounded-sm px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary',
              isActive
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )
          }
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden w-52 shrink-0 border-r border-border bg-surface p-4 md:block">
      <div className="px-2 mb-6 flex items-center gap-2">
        <img src={Logo} alt="ArgusProwl" className="w-8 h-8" />
        <div>
          <h1 className="text-sm font-bold tracking-tight text-foreground uppercase">ArgusProwl</h1>
          <p className="mt-0.5 text-[10px] text-muted-foreground font-mono">THREAT HUNTER CONSOLE</p>
        </div>
      </div>
      <NavItems className="flex flex-col gap-0.5" />
      <div className="mt-auto pt-8 px-2">
        <p className="text-[10px] font-mono text-muted-foreground/50">System v0.1.0-B</p>
      </div>
    </aside>
  );
}

export function Header() {
  return (
    <header className="border-b border-border bg-surface px-4 py-2 sm:px-6">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <p className="text-xs font-semibold text-foreground uppercase tracking-wider">Operations Dashboard</p>
          <div className="h-3 w-px bg-border" />
          <p className="text-[10px] text-muted-foreground font-mono uppercase">System Active</p>
        </div>
        <p className="hidden text-[10px] font-mono text-muted-foreground sm:block">READ-ONLY API VIEW</p>
      </div>
    </header>
  );
}

export function MobileNav() {
  return (
    <div className="border-t border-border bg-popover px-2 py-2 md:hidden">
      <NavItems className="flex items-center justify-around" />
    </div>
  );
}
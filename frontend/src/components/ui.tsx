import type { ReactNode } from 'react';
import { cn } from '../lib/utils';

export function Badge({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-sm border px-1.5 py-0 text-[10px] font-mono font-medium uppercase tracking-wider',
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Card({
  children,
  className,
  title,
  description,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <section className={cn('border border-border bg-surface shadow-none', className)}>
      {(title || description || action) && (
        <header className="flex items-start justify-between gap-4 border-b border-border px-3 py-2">
          <div className="flex flex-col">
            {title && <h2 className="text-xs font-bold text-foreground uppercase tracking-tight">{title}</h2>}
            {description && <p className="mt-0.5 text-[11px] text-muted-foreground font-mono">{description}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-3">{children}</div>
    </section>
  );
}

export function Button({
  children,
  className,
  type = 'button',
  onClick,
  disabled = false,
}: {
  children: ReactNode;
  className?: string;
  type?: 'button' | 'submit';
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex items-center justify-center rounded-sm border border-border bg-surface px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
    >
      {children}
    </button>
  );
}
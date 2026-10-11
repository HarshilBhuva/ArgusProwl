import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { AlertLifecycleState, Severity } from '../types/api';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) {
    return 'unknown time';
  }

  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 604800) return `${Math.floor(diffSec / 86400)}d ago`;
  return date.toLocaleDateString();
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return 'unknown';
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return `${days}d ${hours}h`;
}

export function formatTimestamp(dateString: string): string {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) {
    return 'unknown';
  }
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatMetricName(name: string): string {
  return name
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function truncateString(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength - 3)}...`;
}

export function getSeverityBadgeClass(severity: Severity | string): string {
  switch (severity) {
    case 'INFO':
      return 'border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400';
    case 'LOW':
      return 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400';
    case 'MEDIUM':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400';
    case 'HIGH':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-400';
    case 'CRITICAL':
      return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
}

export function getPriorityBadgeClass(priority: string | null): string {
  switch (priority) {
    case 'LOW':
      return 'border-slate-500/30 bg-slate-500/10 text-slate-700 dark:text-slate-400';
    case 'MEDIUM':
      return 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400';
    case 'HIGH':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400';
    case 'CRITICAL':
      return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
}

export function getLifecycleBadgeClass(lifecycle: AlertLifecycleState | string): string {
  switch (lifecycle) {
    case 'OPEN':
      return 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400';
    case 'ACKNOWLEDGED':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400';
    case 'CLOSED':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
}

export function getHealthBadgeClass(status: string): string {
  switch (status.toLowerCase()) {
    case 'healthy':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    case 'degraded':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    case 'unhealthy':
      return 'border-red-500/30 bg-red-500/10 text-red-300';
    default:
      return 'border-border bg-muted text-muted-foreground';
  }
}
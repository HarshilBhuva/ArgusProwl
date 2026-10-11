import { formatRelativeTime } from '../lib/utils';
import { Button } from './ui';

export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-3" role="status" aria-live="polite" aria-label="Loading content">
      {Array.from({ length: lines }).map((_, index) => (
        <div key={index} className="animate-pulse space-y-2">
          <div className="h-4 w-full rounded bg-muted" />
          <div className="h-4 w-4/5 rounded bg-muted" />
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="py-8 text-center" role="status">
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="py-8 text-center" role="alert">
      <p className="text-sm text-muted-foreground">{message}</p>
      {onRetry && (
        <div className="mt-4">
          <Button onClick={onRetry}>Retry</Button>
        </div>
      )}
    </div>
  );
}
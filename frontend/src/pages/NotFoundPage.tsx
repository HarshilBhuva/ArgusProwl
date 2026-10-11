import { Link } from 'react-router-dom';
import { Card } from '../components/ui';

export function NotFoundPage() {
  return (
    <div className="mx-auto max-w-xl space-y-6 py-12 text-center">
      <h1 className="text-3xl font-semibold tracking-tight text-foreground">Page not found</h1>
      <Card>
        <p className="text-sm text-muted-foreground">
          The requested route does not exist in the Phase 7.1-B console.
        </p>
        <Link
          to="/"
          className="mt-4 inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          Return to dashboard
        </Link>
      </Card>
    </div>
  );
}
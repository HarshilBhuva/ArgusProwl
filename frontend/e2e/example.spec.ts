import { test, expect } from '@playwright/test';

test.describe('ArgusProwl Frontend', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/auth/status', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ auth_enabled: false, session_ttl_seconds: 3600 }),
      }),
    );
    await page.goto('/');
  });

  test('should load the application', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /Operations Dashboard/i })).toBeVisible();
  });


  test('should sign in and sign out when API authentication is enabled', async ({ page }) => {
    let authenticated = false;
    const principal = {
      authenticated: true,
      subject: 'e2e-analyst',
      role: 'analyst',
      key_id: 'e2e-key',
    };

    await page.unroute('**/api/v1/auth/status');
    await page.route('**/api/v1/auth/status', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ auth_enabled: true, session_ttl_seconds: 3600 }),
      }),
    );
    await page.route('**/api/v1/auth/me', (route) =>
      route.fulfill({
        status: authenticated ? 200 : 401,
        contentType: 'application/json',
        body: JSON.stringify(authenticated ? principal : { detail: 'Unauthorized' }),
      }),
    );
    await page.route('**/api/v1/auth/session', async (route) => {
      if (route.request().method() === 'DELETE') {
        authenticated = false;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ authenticated: false }),
        });
        return;
      }
      const body = route.request().postDataJSON() as { api_key?: string };
      authenticated = body.api_key === 'e2e-api-key';
      await route.fulfill({
        status: authenticated ? 200 : 401,
        contentType: 'application/json',
        body: JSON.stringify(authenticated ? principal : { detail: 'Invalid API key.' }),
      });
    });

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.getByLabel('API key').fill('e2e-api-key');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('e2e-analyst')).toBeVisible();
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  });

  test('should show navigation links', async ({ page }) => {
    const sidebar = page.getByRole('complementary');
    await expect(sidebar.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: 'Alerts' })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: 'Incidents' })).toBeVisible();
  });
});

import { test, expect } from '@playwright/test';

test.describe('ArgusProwl Frontend', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should load the application', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /Operations Dashboard/i })).toBeVisible();
  });

  test('should show navigation links', async ({ page }) => {
    const sidebar = page.getByRole('complementary');
    await expect(sidebar.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: 'Alerts' })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: 'Incidents' })).toBeVisible();
  });
});

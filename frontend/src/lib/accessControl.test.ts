import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('accessControl', () => {
    beforeEach(() => {
        vi.resetModules();
    });

    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it('normalizes configured audit admin emails', async () => {
        vi.stubEnv('VITE_AUDIT_ADMIN_EMAILS', 'Alice@example.com, bob@example.com , BOB@EXAMPLE.COM ,');

        const { AUDIT_ADMIN_EMAILS, isAuditAdminEmail } = await import('./accessControl');

        expect(AUDIT_ADMIN_EMAILS).toEqual(['alice@example.com', 'bob@example.com']);
        expect(isAuditAdminEmail('alice@example.com')).toBe(true);
        expect(isAuditAdminEmail('BOB@example.com')).toBe(true);
    });

    it('treats missing or blank values as non-admins', async () => {
        vi.stubEnv('VITE_AUDIT_ADMIN_EMAILS', '');

        const { AUDIT_ADMIN_EMAILS, isAuditAdminEmail } = await import('./accessControl');

        expect(AUDIT_ADMIN_EMAILS).toEqual([]);
        expect(isAuditAdminEmail('')).toBe(false);
        expect(isAuditAdminEmail(null)).toBe(false);
        expect(isAuditAdminEmail(undefined)).toBe(false);
    });
});
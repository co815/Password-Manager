const rawAuditAdmins = (import.meta.env.VITE_AUDIT_ADMIN_EMAILS ?? '') as string;

const normalizedAuditAdmins = rawAuditAdmins
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.length > 0);

const auditAdminSet = new Set(normalizedAuditAdmins);

export const AUDIT_ADMIN_EMAILS = Array.from(auditAdminSet);

export function isAuditAdminEmail(email: string | null | undefined): boolean {
    if (!email) {
        return false;
    }
    const normalized = email.trim().toLowerCase();
    if (!normalized) {
        return false;
    }
    return auditAdminSet.has(normalized);
}
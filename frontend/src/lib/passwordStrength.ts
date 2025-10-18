import zxcvbn from 'zxcvbn';

const BREACHED_PASSWORDS = new Set(
    [
        '123456',
        'password',
        '123456789',
        '12345',
        '12345678',
        'qwerty',
        '1234567',
        '111111',
        '123123',
        'abc123',
        'password1',
        'iloveyou',
        '1q2w3e4r',
        'letmein',
        'football',
        'monkey',
        'dragon',
        'shadow',
        'sunshine',
        'trustno1',
        'welcome',
        'admin',
        'passw0rd',
        'master',
        'zaq12wsx',
    ].map((value) => value.toLowerCase())
);

const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;

export type PasswordStrengthAssessment = {
    score: number;
    compromised: boolean;
    suggestions: string[];
    crackTime: string;
};

export function assessPasswordStrength(
    password: string,
    userInputs: Array<string | null | undefined> = []
): PasswordStrengthAssessment {
    const normalizedPassword = password.trim();

    if (!normalizedPassword) {
        return {
            score: 0,
            compromised: false,
            suggestions: ['Enter a password to see its strength.'],
            crackTime: 'less than a second',
        };
    }

    const evaluation = zxcvbn(
        normalizedPassword,
        userInputs
            .map((input) => input?.toString().trim())
            .filter((input): input is string => Boolean(input))
    );

    const compromised = BREACHED_PASSWORDS.has(normalizedPassword.toLowerCase());
    const score = compromised ? 0 : evaluation.score;

    const suggestions: string[] = [];
    if (compromised) {
        suggestions.push('This password appears in known data breaches. Choose a different one.');
    }
    if (evaluation.feedback.warning) {
        suggestions.push(evaluation.feedback.warning);
    }
    suggestions.push(...evaluation.feedback.suggestions);
    if (!suggestions.length) {
        suggestions.push('Great! This password looks strong. Consider storing it securely in your vault.');
    }

    const crackTimeValue = evaluation.crack_times_display.offline_fast_hashing_1e10_per_second;

    return {
        score,
        compromised,
        suggestions,
        crackTime: typeof crackTimeValue === 'number' ? crackTimeValue.toString() : crackTimeValue,
    };
}

export function getPasswordStrengthLabel(score: number): string {
    const clamped = Math.max(0, Math.min(STRENGTH_LABELS.length - 1, Math.round(score)));
    return STRENGTH_LABELS[clamped];
}

export function getPasswordStrengthColor(score: number): string {
    const colors = ['#ef4444', '#f97316', '#facc15', '#22c55e', '#16a34a'] as const;
    const clamped = Math.max(0, Math.min(colors.length - 1, Math.round(score)));
    return colors[clamped];
}

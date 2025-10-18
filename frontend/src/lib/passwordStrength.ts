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
export const MIN_ACCEPTABLE_PASSWORD_SCORE = 2;

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
    const rawScore = compromised ? 0 : evaluation.score;

    const characterSetsUsed = [
        /[a-z]/.test(normalizedPassword),
        /[A-Z]/.test(normalizedPassword),
        /[0-9]/.test(normalizedPassword),
        /[^A-Za-z0-9]/.test(normalizedPassword),
    ].filter(Boolean).length;

    const heuristicsWarnings: string[] = [];
    let score = rawScore;

    if (characterSetsUsed <= 1) {
        score = Math.min(score, 1);
        heuristicsWarnings.push(
            'Mix in uppercase letters, numbers, or symbols so your password is not made from just one type of character.'
        );
    } else if (characterSetsUsed === 2) {
        score = Math.min(score, 2);
        heuristicsWarnings.push('Using three or more types of characters makes passwords much harder to guess.');
    }

    if (normalizedPassword.length < 12) {
        score = Math.min(score, 2);
        heuristicsWarnings.push('Add a few more characters—longer passwords are significantly stronger.');
    }

    const guessesLog10 = evaluation.guesses_log10 ?? Math.log10(Math.max(1, evaluation.guesses));
    if (guessesLog10 < 6) {
        score = Math.min(score, 1);
        heuristicsWarnings.push('This password would be cracked almost instantly. Use a longer and more complex password.');
    } else if (guessesLog10 < 8) {
        score = Math.min(score, 2);
        heuristicsWarnings.push('Increase the complexity so it takes far longer to crack.');
    }

    const suggestions: string[] = [];
    if (compromised) {
        suggestions.push('This password appears in known data breaches. Choose a different one.');
    }
    suggestions.push(...heuristicsWarnings);
    if (evaluation.feedback.warning) {
        suggestions.push(evaluation.feedback.warning);
    }
    suggestions.push(...evaluation.feedback.suggestions);

    const normalizedSuggestions = suggestions
        .map((suggestion) => suggestion.trim())
        .filter((suggestion) => suggestion.length > 0);

    const uniqueSuggestions = Array.from(new Set(normalizedSuggestions));

    if (!uniqueSuggestions.length) {
        uniqueSuggestions.push('Great! This password looks strong. Consider storing it securely in your vault.');
    }

    const crackTimeValue =
        evaluation.crack_times_display.offline_slow_hashing_1e4_per_second ??
        evaluation.crack_times_display.offline_fast_hashing_1e10_per_second;

    return {
        score,
        compromised,
        suggestions: uniqueSuggestions,
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

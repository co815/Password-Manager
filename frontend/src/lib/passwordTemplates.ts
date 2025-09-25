export type PasswordTemplate = {
    id: string;
    label: string;
    description: string;
    generate: () => string;
};

function cryptoRandomInt(maxExclusive: number): number {
    if (maxExclusive <= 0) {
        throw new RangeError('maxExclusive must be positive');
    }
    const array = new Uint32Array(1);
    const maxUint32 = 0xffffffff;
    let randomValue = 0;
    do {
        crypto.getRandomValues(array);
        randomValue = array[0];
    } while (randomValue > maxUint32 - (maxUint32 % maxExclusive));
    return randomValue % maxExclusive;
}

function shuffle<T>(items: T[]): T[] {
    const result = [...items];
    for (let i = result.length - 1; i > 0; i -= 1) {
        const j = cryptoRandomInt(i + 1);
        [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
}

function randomCharFromSet(charset: string): string {
    if (!charset) {
        throw new Error('Character set must not be empty');
    }
    const index = cryptoRandomInt(charset.length);
    return charset[index] ?? '';
}

function generateFromSets(length: number, sets: string[]): string {
    const sanitizedSets = sets.filter((set) => set.length > 0);
    if (length <= 0 || sanitizedSets.length === 0) {
        return '';
    }

    const mergedSet = sanitizedSets.join('');
    const chars: string[] = [];

    sanitizedSets.forEach((set) => {
        if (chars.length < length) {
            chars.push(randomCharFromSet(set));
        }
    });

    while (chars.length < length) {
        chars.push(randomCharFromSet(mergedSet));
    }

    return shuffle(chars).join('');
}

const WORD_LIST = [
    'atlas', 'ember', 'velvet', 'cobalt', 'sonic', 'orbit', 'breeze', 'harbor', 'quantum', 'pixel',
    'aurora', 'lumen', 'delta', 'falcon', 'nectar', 'plasma', 'ripple', 'solstice', 'zenith', 'violet',
    'ember', 'fable', 'meadow', 'onyx', 'raven', 'signal', 'tango', 'vector', 'willow', 'zephyr',
    'cosmic', 'cipher', 'drift', 'echo', 'flux', 'glacier', 'horizon', 'ion', 'jigsaw', 'krypton',
    'labyrinth', 'mirage', 'nebula', 'obsidian', 'prairie', 'quartz', 'radiant', 'saffron', 'topaz', 'ultra',
    'voyage', 'whisper', 'xenon', 'yonder', 'zen', 'blossom', 'cascade', 'dynamo', 'emberly', 'fusion',
];

function generatePassphrase(words: number): string {
    const count = Math.max(2, words);
    const chosen: string[] = [];
    for (let i = 0; i < count; i += 1) {
        const word = WORD_LIST[cryptoRandomInt(WORD_LIST.length)];
        chosen.push(word);
    }
    return chosen.join('-');
}

export const passwordTemplates: PasswordTemplate[] = [
    {
        id: 'strong-16',
        label: 'Strong (16 characters)',
        description: 'Letters, numbers & symbols for high security.',
        generate: () => generateFromSets(16, [
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            '!@#$%^&*()-_=+[]{};:,.<>?'
        ]),
    },
    {
        id: 'balanced-12',
        label: 'Balanced (12 characters)',
        description: 'Easy to type mix of letters and numbers.',
        generate: () => generateFromSets(12, [
            'ABCDEFGHJKLMNPQRSTUVWXYZ',
            'abcdefghijkmnopqrstuvwxyz',
            '23456789'
        ]),
    },
    {
        id: 'pin-6',
        label: 'PIN (6 digits)',
        description: 'Digits only for devices or legacy systems.',
        generate: () => generateFromSets(6, ['0123456789']),
    },
    {
        id: 'passphrase-4',
        label: 'Passphrase (4 words)',
        description: 'Memorable hyphenated words.',
        generate: () => generatePassphrase(4),
    },
];

export function generatePasswordById(templateId: string): string | null {
    const template = passwordTemplates.find((item) => item.id === templateId);
    return template ? template.generate() : null;
}
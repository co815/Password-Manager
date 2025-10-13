import {ApiError} from './api';

type ApiErrorPayload = {
    message?: unknown;
    error?: unknown;
};

function normalizeUnknown(value: unknown): string {
    if (typeof value === 'string') {
        return value.trim();
    }
    if (value == null) {
        return '';
    }
    return String(value).trim();
}

export function extractApiErrorDetails(error: ApiError): {message: string; errorCode: string} {
    const payload = typeof error.data === 'object' && error.data !== null
        ? (error.data as ApiErrorPayload)
        : undefined;
    const payloadMessage = payload ? normalizeUnknown(payload.message) : '';
    const errorCode = payload ? normalizeUnknown(payload.error) : '';
    const primaryMessage = normalizeUnknown(error.message);

    return {
        message: primaryMessage || payloadMessage,
        errorCode,
    };
}
import {useCallback, useEffect, useMemo, useState} from 'react';
import {useNavigate} from 'react-router-dom';
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    Paper,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import {api, type AuditLogEntry} from '../lib/api';

function formatTimestamp(value: string | null | undefined) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
}

function formatActor(entry: AuditLogEntry) {
    const actor = entry.actor;
    if (!actor) return 'Unknown user';
    if (actor.email) return actor.email;
    if (actor.username) return actor.username;
    return actor.id;
}

function formatTarget(entry: AuditLogEntry) {
    const parts = [entry.targetType].filter(Boolean);
    if (entry.targetId) {
        parts.push(`#${entry.targetId}`);
    }
    return parts.length ? parts.join(' ') : '—';
}

export default function AuditLog() {
    const navigate = useNavigate();
    const [logs, setLogs] = useState<AuditLogEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const loadLogs = useCallback(async (initial: boolean) => {
        if (initial) {
            setLoading(true);
        } else {
            setRefreshing(true);
        }
        try {
            const response = await api.listAuditLogs();
            setLogs(response.logs ?? []);
            setError(null);
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : 'Failed to load audit logs';
            setError(message || 'Failed to load audit logs');
        } finally {
            if (initial) {
                setLoading(false);
            } else {
                setRefreshing(false);
            }
        }
    }, []);

    useEffect(() => {
        void loadLogs(true);
    }, [loadLogs]);

    const hasLogs = useMemo(() => logs.length > 0, [logs]);

    return (
        <Box py={4}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={2} mb={3}>
                <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
                    <Button
                        variant="outlined"
                        size="small"
                        startIcon={<ArrowBackIcon fontSize="small" />}
                        onClick={() => navigate('/dashboard')}
                    >
                        Back to dashboard
                    </Button>
                    <Typography variant="h4" component="h1">
                        Audit log
                    </Typography>
                </Stack>
                <Button
                    variant="outlined"
                    size="small"
                    startIcon={<RefreshIcon fontSize="small" />}
                    onClick={() => void loadLogs(false)}
                    disabled={loading || refreshing}
                >
                    {refreshing ? 'Refreshing…' : 'Refresh'}
                </Button>
            </Stack>

            {error && (
                <Alert severity="error" sx={{mb: 3}}>
                    {error}
                </Alert>
            )}

            <TableContainer component={Paper}>
                {loading ? (
                    <Box display="flex" justifyContent="center" alignItems="center" minHeight={240}>
                        <CircularProgress />
                    </Box>
                ) : !hasLogs ? (
                    <Box p={3} textAlign="center">
                        <Typography variant="body1" gutterBottom>
                            No audit entries yet.
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                            Actions from the backend will appear here once they are recorded.
                        </Typography>
                    </Box>
                ) : (
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{width: 220}}>Timestamp</TableCell>
                                <TableCell sx={{width: 220}}>Actor</TableCell>
                                <TableCell>Action</TableCell>
                                <TableCell>Target</TableCell>
                                <TableCell>Details</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {logs.map((entry) => (
                                <TableRow key={entry.id} hover>
                                    <TableCell>{formatTimestamp(entry.createdDate)}</TableCell>
                                    <TableCell>{formatActor(entry)}</TableCell>
                                    <TableCell sx={{textTransform: 'capitalize'}}>{entry.action.toLowerCase()}</TableCell>
                                    <TableCell>{formatTarget(entry)}</TableCell>
                                    <TableCell sx={{whiteSpace: 'pre-wrap', wordBreak: 'break-word'}}>
                                        {entry.details ?? '—'}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                )}
            </TableContainer>
        </Box>
    );
}
import {useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent} from 'react';
import {useNavigate} from 'react-router-dom';
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    Divider,
    FormControl,
    InputLabel,
    MenuItem,
    Paper,
    Select,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TablePagination,
    TableRow,
    TextField,
    Typography,
} from '@mui/material';
import type {SelectChangeEvent} from '@mui/material/Select';
import RefreshIcon from '@mui/icons-material/Refresh';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DownloadIcon from '@mui/icons-material/Download';
import {api, type AuditLogEntry, type AuditLogListParams} from '../lib/api';

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

type FilterState = {
    search: string;
    action: string;
    targetType: string;
    targetId: string;
    actor: string;
    from: string;
    to: string;
};

type ExportFormat = 'csv' | 'json';

const DEFAULT_FILTERS: FilterState = {
    search: '',
    action: '',
    targetType: '',
    targetId: '',
    actor: '',
    from: '',
    to: '',
};

const EXPORT_LIMIT = 5000;

function toIsoStart(value: string): string | undefined {
    if (!value) return undefined;
    const date = new Date(`${value}T00:00:00.000Z`);
    if (Number.isNaN(date.getTime())) return undefined;
    return date.toISOString();
}

function toIsoEnd(value: string): string | undefined {
    if (!value) return undefined;
    const date = new Date(`${value}T23:59:59.999Z`);
    if (Number.isNaN(date.getTime())) return undefined;
    return date.toISOString();
}

export default function AuditLog() {
    const navigate = useNavigate();
    const [logs, setLogs] = useState<AuditLogEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [exporting, setExporting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [page, setPage] = useState(0);
    const [pageSize, setPageSize] = useState(50);
    const [totalElements, setTotalElements] = useState(0);
    const [filters, setFilters] = useState<FilterState>({...DEFAULT_FILTERS});
    const [draftFilters, setDraftFilters] = useState<FilterState>({...DEFAULT_FILTERS});
    const [exportFormat, setExportFormat] = useState<ExportFormat>('csv');
    const firstLoad = useRef(true);
    const pageRef = useRef(page);
    const pageSizeRef = useRef(pageSize);
    const totalElementsRef = useRef(totalElements);

    useEffect(() => {
        pageRef.current = page;
    }, [page]);

    useEffect(() => {
        pageSizeRef.current = pageSize;
    }, [pageSize]);

    useEffect(() => {
        totalElementsRef.current = totalElements;
    }, [totalElements]);

    const buildParams = useCallback((options?: {includePagination?: boolean; limit?: number}): AuditLogListParams => {
        const includePagination = options?.includePagination ?? true;
        const params: AuditLogListParams = {};
        if (includePagination) {
            params.page = page;
            params.pageSize = pageSize;
        }
        if (filters.search) {
            params.search = filters.search;
        }
        if (filters.action) {
            params.actions = [filters.action];
        }
        if (filters.targetType) {
            params.targetTypes = [filters.targetType];
        }
        if (filters.targetId) {
            params.targetId = filters.targetId;
        }
        if (filters.actor) {
            params.actor = filters.actor;
        }
        const fromIso = toIsoStart(filters.from);
        if (fromIso) {
            params.from = fromIso;
        }
        const toIso = toIsoEnd(filters.to);
        if (toIso) {
            params.to = toIso;
        }
        if (typeof options?.limit === 'number') {
            params.limit = options.limit;
        }
        return params;
    }, [filters, page, pageSize]);

    const loadLogs = useCallback(async (initial: boolean) => {
        if (initial) {
            setLoading(true);
        } else {
            setRefreshing(true);
        }
        try {
            const response = await api.listAuditLogs(buildParams());
            setLogs(response.logs ?? []);

            const responsePageSize = typeof response.pageSize === 'number' ? response.pageSize : undefined;
            const responseTotalElements = typeof response.totalElements === 'number' ? response.totalElements : undefined;
            const responsePage = typeof response.page === 'number' ? response.page : undefined;

            const nextPageSize = responsePageSize ?? pageSizeRef.current;
            setPageSize((prevPageSize) => (nextPageSize !== prevPageSize ? nextPageSize : prevPageSize));

            const nextTotalElements = responseTotalElements ?? totalElementsRef.current;
            setTotalElements((prevTotalElements) => (nextTotalElements !== prevTotalElements ? nextTotalElements : prevTotalElements));

            const totalPagesFromResponse = typeof response.totalPages === 'number'
                ? response.totalPages
                : nextPageSize > 0
                    ? Math.ceil(nextTotalElements / nextPageSize)
                    : 0;

            if (typeof responsePage === 'number') {
                const clampedPage = totalPagesFromResponse > 0
                    ? Math.min(responsePage, totalPagesFromResponse - 1)
                    : 0;
                setPage((prevPage) => (prevPage !== clampedPage ? clampedPage : prevPage));
            }
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
    }, [buildParams]);

    useEffect(() => {
        const initial = firstLoad.current;
        firstLoad.current = false;
        void loadLogs(initial);
    }, [loadLogs]);

    const hasLogs = useMemo(() => logs.length > 0, [logs]);

    const handleDraftChange = useCallback((key: keyof FilterState, value: string) => {
        setDraftFilters((prev) => ({
            ...prev,
            [key]: value,
        }));
    }, []);

    const handleApplyFilters = useCallback(() => {
        setFilters({...draftFilters});
        setPage(0);
    }, [draftFilters]);

    const handleResetFilters = useCallback(() => {
        setDraftFilters({...DEFAULT_FILTERS});
        setFilters({...DEFAULT_FILTERS});
        setPage(0);
        setPageSize(50);
        setExportFormat('csv');
    }, []);

    const handlePageChange = useCallback((_: unknown, newPage: number) => {
        setPage(newPage);
    }, []);

    const handleRowsPerPageChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
        const next = Number.parseInt(event.target.value, 10);
        if (Number.isNaN(next)) {
            return;
        }
        setPageSize(next);
        setPage(0);
    }, []);

    const handleExport = useCallback(async () => {
        setExporting(true);
        try {
            const baseParams = buildParams({includePagination: false, limit: EXPORT_LIMIT});
            const blob = await api.exportAuditLogs({...baseParams, format: exportFormat});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const extension = exportFormat === 'json' ? 'json' : 'csv';
            link.download = `audit-log-${timestamp}.${extension}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : 'Failed to export audit logs';
            setError(message || 'Failed to export audit logs');
        } finally {
            setExporting(false);
        }
    }, [buildParams, exportFormat]);

    const handleExportFormatChange = useCallback((event: SelectChangeEvent<ExportFormat>) => {
        const value = event.target.value as ExportFormat;
        setExportFormat(value);
    }, []);

    return (
        <Box sx={{paddingTop: (theme) => theme.spacing(4), paddingBottom: (theme) => theme.spacing(4)}}>
            <Stack
                direction="row"
                alignItems="center"
                justifyContent="space-between"
                flexWrap="wrap"
                gap={2}
                sx={{marginBottom: (theme) => theme.spacing(3)}}
            >
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

            <Paper sx={{marginBottom: (theme) => theme.spacing(3), padding: (theme) => theme.spacing(2)}}>
                <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between" flexWrap="wrap" mb={2}>
                    <Typography variant="h6">Filters</Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                        <Button variant="outlined" size="small" onClick={handleResetFilters} disabled={loading || refreshing}>
                            Reset
                        </Button>
                        <Button
                            variant="contained"
                            size="small"
                            onClick={handleApplyFilters}
                            disabled={loading || refreshing}
                        >
                            Apply filters
                        </Button>
                        <FormControl size="small" sx={{minWidth: 160}}>
                            <InputLabel id="audit-log-export-format-label">Export format</InputLabel>
                            <Select
                                labelId="audit-log-export-format-label"
                                value={exportFormat}
                                label="Export format"
                                onChange={handleExportFormatChange}
                            >
                                <MenuItem value="csv">CSV</MenuItem>
                                <MenuItem value="json">JSON</MenuItem>
                            </Select>
                        </FormControl>
                        <Button
                            variant="contained"
                            color="secondary"
                            size="small"
                            startIcon={<DownloadIcon fontSize="small" />}
                            onClick={() => void handleExport()}
                            disabled={loading || refreshing || exporting}
                        >
                            {exporting ? 'Exporting…' : `Export ${exportFormat.toUpperCase()}`}
                        </Button>
                    </Stack>
                </Stack>
                <Divider sx={{marginBottom: (theme) => theme.spacing(2)}} />
                <Stack direction="row" spacing={2} useFlexGap flexWrap="wrap">
                    <TextField
                        label="Search"
                        value={draftFilters.search}
                        size="small"
                        onChange={(event) => handleDraftChange('search', event.target.value)}
                        sx={{minWidth: 220}}
                    />
                    <TextField
                        label="Action"
                        value={draftFilters.action}
                        size="small"
                        onChange={(event) => handleDraftChange('action', event.target.value)}
                        sx={{minWidth: 160}}
                        placeholder="e.g. LOGIN"
                    />
                    <TextField
                        label="Target type"
                        value={draftFilters.targetType}
                        size="small"
                        onChange={(event) => handleDraftChange('targetType', event.target.value)}
                        sx={{minWidth: 160}}
                    />
                    <TextField
                        label="Target ID"
                        value={draftFilters.targetId}
                        size="small"
                        onChange={(event) => handleDraftChange('targetId', event.target.value)}
                        sx={{minWidth: 160}}
                    />
                    <TextField
                        label="Actor (email, username or ID)"
                        value={draftFilters.actor}
                        size="small"
                        onChange={(event) => handleDraftChange('actor', event.target.value)}
                        sx={{minWidth: 220}}
                    />
                    <TextField
                        label="From"
                        type="date"
                        value={draftFilters.from}
                        size="small"
                        onChange={(event) => handleDraftChange('from', event.target.value)}
                        InputLabelProps={{shrink: true}}
                    />
                    <TextField
                        label="To"
                        type="date"
                        value={draftFilters.to}
                        size="small"
                        onChange={(event) => handleDraftChange('to', event.target.value)}
                        InputLabelProps={{shrink: true}}
                    />
                </Stack>
            </Paper>

            {error && (
                <Alert
                    severity="error"
                    sx={{marginBottom: (theme) => theme.spacing(3)}}
                >
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
            {hasLogs && (
                <TablePagination
                    component="div"
                    count={totalElements}
                    page={page}
                    onPageChange={handlePageChange}
                    rowsPerPage={pageSize}
                    onRowsPerPageChange={handleRowsPerPageChange}
                    rowsPerPageOptions={[25, 50, 100, 200]}
                    showFirstButton
                    showLastButton
                />
            )}
        </Box>
    );
} 

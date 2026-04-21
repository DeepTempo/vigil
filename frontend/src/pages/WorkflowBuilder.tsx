import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Snackbar,
  Stack,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
} from '@mui/material'
import {
  Add as AddIcon,
  ArrowDownward as DownIcon,
  ArrowUpward as UpIcon,
  AutoAwesome as AIIcon,
  Close as CloseIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  PlayArrow as PlayIcon,
  Save as SaveIcon,
} from '@mui/icons-material'
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { workflowApi, type WorkflowPhase } from '../services/api'

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

interface WorkflowListItem {
  id: string
  name: string
  description: string
  agents: string[]
  tools_used: string[]
  use_case: string
  trigger_examples: string[]
  source?: 'file' | 'custom'
  phases?: WorkflowPhase[]
}

interface CustomWorkflowRecord {
  workflow_id: string
  name: string
  description: string
  use_case?: string
  trigger_examples: string[]
  phases: WorkflowPhase[]
  graph_layout?: Record<string, any>
  is_active: boolean
  version: number
}

type View = 'list' | 'editor'

// Known built-in agent IDs mapped to readable labels (matches soc_agents.py)
const AGENT_OPTIONS: Array<{ id: string; label: string }> = [
  { id: 'triage', label: 'Triage Agent' },
  { id: 'investigator', label: 'Investigation Agent' },
  { id: 'threat_hunter', label: 'Threat Hunter' },
  { id: 'correlator', label: 'Correlator' },
  { id: 'responder', label: 'Responder' },
  { id: 'reporter', label: 'Reporter' },
  { id: 'mitre_analyst', label: 'MITRE Analyst' },
  { id: 'forensics', label: 'Forensics' },
  { id: 'threat_intel', label: 'Threat Intel' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'malware_analyst', label: 'Malware Analyst' },
  { id: 'network_analyst', label: 'Network Analyst' },
]

const emptyPhase = (order: number): WorkflowPhase => ({
  phase_id: `phase-${order}`,
  order,
  agent_id: 'triage',
  name: `Phase ${order}`,
  purpose: '',
  tools: [],
  steps: [],
  expected_output: '',
  timeout_seconds: 300,
  approval_required: false,
})

interface EditorState {
  workflow_id: string | null // null when unsaved
  name: string
  description: string
  use_case: string
  trigger_examples: string[]
  phases: WorkflowPhase[]
}

const emptyEditor = (): EditorState => ({
  workflow_id: null,
  name: '',
  description: '',
  use_case: '',
  trigger_examples: [],
  phases: [emptyPhase(1)],
})

// -----------------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------------

export default function WorkflowBuilder() {
  const theme = useTheme()
  const isDark = theme.palette.mode === 'dark'

  const [view, setView] = useState<View>('list')
  const [workflows, setWorkflows] = useState<WorkflowListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [editor, setEditor] = useState<EditorState>(emptyEditor())
  const [saving, setSaving] = useState(false)

  const [generateOpen, setGenerateOpen] = useState(false)
  const [generatePrompt, setGeneratePrompt] = useState('')
  const [generating, setGenerating] = useState(false)

  const [executeOpen, setExecuteOpen] = useState(false)
  const [executeTarget, setExecuteTarget] = useState<WorkflowListItem | null>(null)
  const [executeParams, setExecuteParams] = useState({
    finding_id: '',
    case_id: '',
    context: '',
    hypothesis: '',
  })
  const [executing, setExecuting] = useState(false)

  const [snackbar, setSnackbar] = useState<{
    open: boolean
    message: string
    severity: 'success' | 'error' | 'info'
  }>({ open: false, message: '', severity: 'info' })

  const notify = (message: string, severity: 'success' | 'error' | 'info' = 'info') =>
    setSnackbar({ open: true, message, severity })

  // ---------- Load list ------------------------------------------------------

  const loadWorkflows = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await workflowApi.listAll()
      setWorkflows(res.data.workflows || [])
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load workflows')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadWorkflows()
  }, [loadWorkflows])

  // ---------- Editor actions -------------------------------------------------

  const openNewEditor = () => {
    setEditor(emptyEditor())
    setView('editor')
  }

  const openEditWorkflow = async (wf: WorkflowListItem) => {
    if (wf.source !== 'custom') {
      notify('File-based workflows are not editable here.', 'info')
      return
    }
    try {
      const res = await workflowApi.getCustom(wf.id)
      const full: CustomWorkflowRecord = res.data
      setEditor({
        workflow_id: full.workflow_id,
        name: full.name,
        description: full.description,
        use_case: full.use_case || '',
        trigger_examples: full.trigger_examples || [],
        phases: (full.phases || []).map((p, i) => ({
          ...emptyPhase(i + 1),
          ...p,
          order: i + 1,
        })),
      })
      setView('editor')
    } catch (err: any) {
      notify(err.response?.data?.detail || 'Failed to load workflow', 'error')
    }
  }

  const saveEditor = async () => {
    if (!editor.name.trim() || !editor.description.trim()) {
      notify('Name and description are required.', 'error')
      return
    }
    if (editor.phases.length === 0) {
      notify('Add at least one phase.', 'error')
      return
    }
    setSaving(true)
    const payload = {
      name: editor.name.trim(),
      description: editor.description.trim(),
      use_case: editor.use_case.trim(),
      trigger_examples: editor.trigger_examples.filter((t) => t.trim()),
      phases: editor.phases.map((p, i) => ({
        ...p,
        order: i + 1,
        phase_id: p.phase_id || `phase-${i + 1}`,
      })),
    }
    try {
      if (editor.workflow_id) {
        await workflowApi.updateCustom(editor.workflow_id, payload)
        notify('Workflow updated.', 'success')
      } else {
        const res = await workflowApi.createCustom(payload)
        setEditor((e) => ({ ...e, workflow_id: res.data.workflow_id }))
        notify('Workflow created.', 'success')
      }
      await loadWorkflows()
      setView('list')
    } catch (err: any) {
      notify(err.response?.data?.detail || 'Save failed', 'error')
    } finally {
      setSaving(false)
    }
  }

  const deleteWorkflow = async (wf: WorkflowListItem) => {
    if (wf.source !== 'custom') return
    if (!window.confirm(`Deactivate workflow "${wf.name}"?`)) return
    try {
      await workflowApi.deleteCustom(wf.id)
      notify('Workflow deactivated.', 'success')
      await loadWorkflows()
    } catch (err: any) {
      notify(err.response?.data?.detail || 'Delete failed', 'error')
    }
  }

  // ---------- Generation -----------------------------------------------------

  const runGenerate = async () => {
    if (!generatePrompt.trim()) {
      notify('Describe the scenario first.', 'error')
      return
    }
    setGenerating(true)
    try {
      const res = await workflowApi.generate(generatePrompt.trim())
      const draft = res.data.draft
      setEditor({
        workflow_id: null,
        name: draft.name || '',
        description: draft.description || '',
        use_case: draft.use_case || '',
        trigger_examples: draft.trigger_examples || [],
        phases: (draft.phases || []).map((p: WorkflowPhase, i: number) => ({
          ...emptyPhase(i + 1),
          ...p,
          order: i + 1,
        })),
      })
      setGenerateOpen(false)
      setGeneratePrompt('')
      setView('editor')
      notify('Draft generated. Review and save.', 'success')
    } catch (err: any) {
      notify(err.response?.data?.detail || 'Generation failed', 'error')
    } finally {
      setGenerating(false)
    }
  }

  // ---------- Execution ------------------------------------------------------

  const runExecute = async () => {
    if (!executeTarget) return
    const params: Record<string, string> = {}
    for (const [k, v] of Object.entries(executeParams)) {
      if (v.trim()) params[k] = v.trim()
    }
    if (Object.keys(params).length === 0) {
      notify('Provide at least one parameter.', 'error')
      return
    }
    setExecuting(true)
    try {
      await workflowApi.execute(executeTarget.id, params)
      notify(`Workflow "${executeTarget.name}" executed.`, 'success')
      setExecuteOpen(false)
      setExecuteTarget(null)
      setExecuteParams({ finding_id: '', case_id: '', context: '', hypothesis: '' })
    } catch (err: any) {
      notify(err.response?.data?.detail || 'Execution failed', 'error')
    } finally {
      setExecuting(false)
    }
  }

  // ---------- Render ---------------------------------------------------------

  if (view === 'editor') {
    return (
      <EditorView
        editor={editor}
        setEditor={setEditor}
        saving={saving}
        onCancel={() => setView('list')}
        onSave={saveEditor}
        snackbar={snackbar}
        setSnackbar={setSnackbar}
        isDark={isDark}
      />
    )
  }

  return (
    <Box sx={{ p: 3 }}>
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700 }}>
            Workflow Builder
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Create, customize, and execute multi-agent workflows.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            startIcon={<AIIcon />}
            onClick={() => setGenerateOpen(true)}
          >
            Generate with AI
          </Button>
          <Button variant="contained" startIcon={<AddIcon />} onClick={openNewEditor}>
            New Workflow
          </Button>
        </Stack>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      ) : (
        <Grid container spacing={2}>
          {workflows.map((wf) => (
            <Grid item xs={12} md={6} lg={4} key={wf.id}>
              <Card
                sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  borderLeft: 4,
                  borderColor:
                    wf.source === 'custom' ? 'primary.main' : alpha(theme.palette.text.primary, 0.3),
                }}
              >
                <CardContent sx={{ flex: 1 }}>
                  <Stack
                    direction="row"
                    justifyContent="space-between"
                    alignItems="flex-start"
                    sx={{ mb: 1 }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      {wf.name}
                    </Typography>
                    <Chip
                      size="small"
                      label={wf.source === 'custom' ? 'Custom' : 'Built-in'}
                      color={wf.source === 'custom' ? 'primary' : 'default'}
                    />
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {wf.description}
                  </Typography>
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {(wf.agents || []).slice(0, 6).map((a) => (
                      <Chip key={a} size="small" label={a} variant="outlined" />
                    ))}
                  </Stack>
                </CardContent>
                <CardActions>
                  <Button
                    size="small"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      setExecuteTarget(wf)
                      setExecuteOpen(true)
                    }}
                  >
                    Execute
                  </Button>
                  <Button
                    size="small"
                    startIcon={<EditIcon />}
                    disabled={wf.source !== 'custom'}
                    onClick={() => openEditWorkflow(wf)}
                  >
                    Edit
                  </Button>
                  <Button
                    size="small"
                    color="error"
                    startIcon={<DeleteIcon />}
                    disabled={wf.source !== 'custom'}
                    onClick={() => deleteWorkflow(wf)}
                  >
                    Delete
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
          {workflows.length === 0 && (
            <Grid item xs={12}>
              <Alert severity="info">
                No workflows yet. Click "New Workflow" or "Generate with AI" to create one.
              </Alert>
            </Grid>
          )}
        </Grid>
      )}

      {/* Generate dialog */}
      <Dialog
        open={generateOpen}
        onClose={() => !generating && setGenerateOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Generate Workflow with AI</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Describe the security scenario in plain English. The AI will draft a multi-phase
            workflow you can edit before saving.
          </Typography>
          <TextField
            autoFocus
            multiline
            minRows={4}
            fullWidth
            label="Scenario description"
            placeholder="e.g. Investigate suspicious login activity and contain the account if credentials look compromised."
            value={generatePrompt}
            onChange={(e) => setGeneratePrompt(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGenerateOpen(false)} disabled={generating}>
            Cancel
          </Button>
          <Button
            variant="contained"
            startIcon={generating ? <CircularProgress size={16} /> : <AIIcon />}
            disabled={generating}
            onClick={runGenerate}
          >
            Generate Draft
          </Button>
        </DialogActions>
      </Dialog>

      {/* Execute dialog */}
      <Dialog
        open={executeOpen}
        onClose={() => !executing && setExecuteOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Execute: {executeTarget?.name}
          <IconButton
            onClick={() => setExecuteOpen(false)}
            size="small"
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Finding ID"
              value={executeParams.finding_id}
              onChange={(e) =>
                setExecuteParams((p) => ({ ...p, finding_id: e.target.value }))
              }
              placeholder="f-YYYYMMDD-XXXXXXXX"
              fullWidth
            />
            <TextField
              label="Case ID"
              value={executeParams.case_id}
              onChange={(e) => setExecuteParams((p) => ({ ...p, case_id: e.target.value }))}
              fullWidth
            />
            <TextField
              label="Hypothesis"
              value={executeParams.hypothesis}
              onChange={(e) =>
                setExecuteParams((p) => ({ ...p, hypothesis: e.target.value }))
              }
              fullWidth
              multiline
              minRows={2}
            />
            <TextField
              label="Additional context"
              value={executeParams.context}
              onChange={(e) => setExecuteParams((p) => ({ ...p, context: e.target.value }))}
              fullWidth
              multiline
              minRows={2}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExecuteOpen(false)} disabled={executing}>
            Cancel
          </Button>
          <Button
            variant="contained"
            startIcon={executing ? <CircularProgress size={16} /> : <PlayIcon />}
            disabled={executing}
            onClick={runExecute}
          >
            Execute
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar((s) => ({ ...s, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  )
}

// -----------------------------------------------------------------------------
// Editor view — form (left) + xyflow canvas preview (right)
// -----------------------------------------------------------------------------

interface EditorViewProps {
  editor: EditorState
  setEditor: React.Dispatch<React.SetStateAction<EditorState>>
  saving: boolean
  onCancel: () => void
  onSave: () => void
  snackbar: { open: boolean; message: string; severity: 'success' | 'error' | 'info' }
  setSnackbar: React.Dispatch<
    React.SetStateAction<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>
  >
  isDark: boolean
}

function EditorView({
  editor,
  setEditor,
  saving,
  onCancel,
  onSave,
  snackbar,
  setSnackbar,
  isDark,
}: EditorViewProps) {
  const { nodes, edges } = useMemo(() => buildGraph(editor.phases), [editor.phases])

  const updatePhase = (idx: number, patch: Partial<WorkflowPhase>) => {
    setEditor((e) => {
      const next = [...e.phases]
      next[idx] = { ...next[idx], ...patch }
      return { ...e, phases: next }
    })
  }

  const movePhase = (idx: number, delta: number) => {
    const target = idx + delta
    setEditor((e) => {
      if (target < 0 || target >= e.phases.length) return e
      const next = [...e.phases]
      const [item] = next.splice(idx, 1)
      next.splice(target, 0, item)
      return {
        ...e,
        phases: next.map((p, i) => ({ ...p, order: i + 1 })),
      }
    })
  }

  const removePhase = (idx: number) => {
    setEditor((e) => ({
      ...e,
      phases: e.phases
        .filter((_, i) => i !== idx)
        .map((p, i) => ({ ...p, order: i + 1, phase_id: p.phase_id || `phase-${i + 1}` })),
    }))
  }

  const addPhase = () => {
    setEditor((e) => {
      const order = e.phases.length + 1
      return { ...e, phases: [...e.phases, emptyPhase(order)] }
    })
  }

  return (
    <Box sx={{ p: 3 }}>
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700 }}>
            {editor.workflow_id ? 'Edit Workflow' : 'New Workflow'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {editor.workflow_id ? editor.workflow_id : 'Draft — not yet saved'}
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button
            variant="contained"
            startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
            disabled={saving}
            onClick={onSave}
          >
            Save
          </Button>
        </Stack>
      </Stack>

      <Grid container spacing={2}>
        <Grid item xs={12} md={7}>
          <Stack spacing={2}>
            <Card>
              <CardContent>
                <Typography variant="subtitle2" sx={{ mb: 2 }}>
                  Workflow Metadata
                </Typography>
                <Stack spacing={2}>
                  <TextField
                    label="Name"
                    required
                    value={editor.name}
                    onChange={(e) => setEditor((x) => ({ ...x, name: e.target.value }))}
                    fullWidth
                  />
                  <TextField
                    label="Description"
                    required
                    value={editor.description}
                    onChange={(e) =>
                      setEditor((x) => ({ ...x, description: e.target.value }))
                    }
                    fullWidth
                    multiline
                    minRows={2}
                  />
                  <TextField
                    label="Use case"
                    value={editor.use_case}
                    onChange={(e) => setEditor((x) => ({ ...x, use_case: e.target.value }))}
                    fullWidth
                  />
                  <TextField
                    label="Trigger examples (one per line)"
                    value={editor.trigger_examples.join('\n')}
                    onChange={(e) =>
                      setEditor((x) => ({
                        ...x,
                        trigger_examples: e.target.value.split('\n'),
                      }))
                    }
                    fullWidth
                    multiline
                    minRows={2}
                  />
                </Stack>
              </CardContent>
            </Card>

            <Card>
              <CardContent>
                <Stack
                  direction="row"
                  alignItems="center"
                  justifyContent="space-between"
                  sx={{ mb: 2 }}
                >
                  <Typography variant="subtitle2">Phases</Typography>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<AddIcon />}
                    onClick={addPhase}
                  >
                    Add Phase
                  </Button>
                </Stack>
                <Stack spacing={2}>
                  {editor.phases.map((phase, idx) => (
                    <PhaseEditor
                      key={phase.phase_id || idx}
                      phase={phase}
                      index={idx}
                      total={editor.phases.length}
                      onChange={(patch) => updatePhase(idx, patch)}
                      onMoveUp={() => movePhase(idx, -1)}
                      onMoveDown={() => movePhase(idx, 1)}
                      onDelete={() => removePhase(idx)}
                    />
                  ))}
                </Stack>
              </CardContent>
            </Card>
          </Stack>
        </Grid>

        <Grid item xs={12} md={5}>
          <Card sx={{ height: '100%', minHeight: 560 }}>
            <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Flow Preview
              </Typography>
              <Divider sx={{ mb: 1 }} />
              <Box sx={{ flex: 1, minHeight: 480 }}>
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  fitView
                  nodesDraggable={false}
                  nodesConnectable={false}
                  elementsSelectable={false}
                  proOptions={{ hideAttribution: true }}
                  colorMode={isDark ? 'dark' : 'light'}
                >
                  <Background />
                  <MiniMap pannable zoomable />
                  <Controls showInteractive={false} />
                </ReactFlow>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  )
}

// -----------------------------------------------------------------------------
// Single-phase editor
// -----------------------------------------------------------------------------

interface PhaseEditorProps {
  phase: WorkflowPhase
  index: number
  total: number
  onChange: (patch: Partial<WorkflowPhase>) => void
  onMoveUp: () => void
  onMoveDown: () => void
  onDelete: () => void
}

function PhaseEditor({
  phase,
  index,
  total,
  onChange,
  onMoveUp,
  onMoveDown,
  onDelete,
}: PhaseEditorProps) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ mb: 1 }}
        >
          <Typography variant="subtitle2">Phase {index + 1}</Typography>
          <Stack direction="row" spacing={0.5}>
            <Tooltip title="Move up">
              <span>
                <IconButton size="small" disabled={index === 0} onClick={onMoveUp}>
                  <UpIcon fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title="Move down">
              <span>
                <IconButton
                  size="small"
                  disabled={index === total - 1}
                  onClick={onMoveDown}
                >
                  <DownIcon fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title="Remove phase">
              <IconButton size="small" color="error" onClick={onDelete}>
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Stack>
        </Stack>

        <Grid container spacing={1.5}>
          <Grid item xs={12} sm={7}>
            <TextField
              label="Phase name"
              value={phase.name}
              onChange={(e) => onChange({ name: e.target.value })}
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={5}>
            <FormControl fullWidth size="small">
              <InputLabel>Agent</InputLabel>
              <Select
                label="Agent"
                value={phase.agent_id}
                onChange={(e) => onChange({ agent_id: e.target.value })}
              >
                {AGENT_OPTIONS.map((a) => (
                  <MenuItem key={a.id} value={a.id}>
                    {a.label} ({a.id})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Purpose"
              value={phase.purpose || ''}
              onChange={(e) => onChange({ purpose: e.target.value })}
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Tools (comma-separated)"
              value={(phase.tools || []).join(', ')}
              onChange={(e) =>
                onChange({
                  tools: e.target.value
                    .split(',')
                    .map((t) => t.trim())
                    .filter(Boolean),
                })
              }
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Steps (one per line)"
              value={(phase.steps || []).join('\n')}
              onChange={(e) =>
                onChange({
                  steps: e.target.value.split('\n').filter((s) => s !== '' || true),
                })
              }
              fullWidth
              multiline
              minRows={2}
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Expected output"
              value={phase.expected_output || ''}
              onChange={(e) => onChange({ expected_output: e.target.value })}
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={6} sm={3}>
            <TextField
              label="Timeout (s)"
              type="number"
              value={phase.timeout_seconds ?? 300}
              onChange={(e) =>
                onChange({ timeout_seconds: parseInt(e.target.value, 10) || 0 })
              }
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={6} sm={3}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={!!phase.approval_required}
                  onChange={(e) => onChange({ approval_required: e.target.checked })}
                />
              }
              label="Approval"
            />
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  )
}

// -----------------------------------------------------------------------------
// Graph builder — linear left-to-right layout
// -----------------------------------------------------------------------------

function buildGraph(phases: WorkflowPhase[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = phases.map((phase, i) => ({
    id: phase.phase_id || `phase-${i + 1}`,
    position: { x: i * 220, y: 0 },
    data: {
      label: (
        <Box sx={{ textAlign: 'center' }}>
          <Typography variant="caption" sx={{ fontWeight: 700 }}>
            {`Phase ${i + 1}`}
          </Typography>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {phase.name || '(unnamed)'}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {phase.agent_id}
          </Typography>
        </Box>
      ),
    },
    style: {
      width: 180,
      padding: 8,
      borderRadius: 8,
      border: phase.approval_required ? '2px solid #ff9800' : '1px solid #888',
    },
  }))

  const edges: Edge[] = []
  for (let i = 0; i < phases.length - 1; i++) {
    const from = phases[i].phase_id || `phase-${i + 1}`
    const to = phases[i + 1].phase_id || `phase-${i + 2}`
    edges.push({
      id: `${from}->${to}`,
      source: from,
      target: to,
      markerEnd: { type: MarkerType.ArrowClosed },
    })
  }
  return { nodes, edges }
}

import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  CircularProgress,
  Alert,
  Chip,
  IconButton,
  Tabs,
  Tab,
  useTheme,
} from '@mui/material'
import {
  Add as AddIcon,
  Refresh as RefreshIcon,
  Timeline as TimelineIcon,
  Launch as LaunchIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material'
import { timesketchApi } from '../services/api'
import { StatCard, SearchInput } from '../components/ui'

interface Sketch {
  id: number
  name: string
  description: string
  created_at: string
  user?: { username: string }
}

interface TabPanelProps {
  children?: React.ReactNode
  index: number
  value: number
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return <div hidden={value !== index}>{value === index && <Box sx={{ pt: 2 }}>{children}</Box>}</div>
}

export default function Timesketch() {
  const theme = useTheme()
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<any>(null)
  const [dockerStatus, setDockerStatus] = useState<any>(null)
  const [sketches, setSketches] = useState<Sketch[]>([])
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [newSketch, setNewSketch] = useState({ name: '', description: '' })
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [currentTab, setCurrentTab] = useState(0)
  const [dockerLoading, setDockerLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [statusRes, dockerRes] = await Promise.all([
        timesketchApi.getStatus(),
        timesketchApi.getDockerStatus(),
      ])
      setStatus(statusRes.data)
      setDockerStatus(dockerRes.data)
      if (statusRes.data.connected) {
        const sketchRes = await timesketchApi.listSketches()
        setSketches(sketchRes.data.sketches || [])
      }
    } catch {
      setMessage({ type: 'error', text: 'Failed to load Timesketch data' })
    } finally {
      setLoading(false)
    }
  }

  const handleCreateSketch = async () => {
    if (!newSketch.name.trim()) {
      setMessage({ type: 'error', text: 'Sketch name is required' })
      return
    }
    try {
      await timesketchApi.createSketch(newSketch)
      setMessage({ type: 'success', text: 'Sketch created successfully' })
      setCreateDialogOpen(false)
      setNewSketch({ name: '', description: '' })
      loadData()
    } catch {
      setMessage({ type: 'error', text: 'Failed to create sketch' })
    }
  }

  const handleStartDocker = async () => {
    setDockerLoading(true)
    try {
      await timesketchApi.startDocker(5000)
      setMessage({ type: 'success', text: 'Container starting...' })
      setTimeout(async () => {
        const res = await timesketchApi.getDockerStatus()
        setDockerStatus(res.data)
        setDockerLoading(false)
      }, 5000)
    } catch {
      setMessage({ type: 'error', text: 'Failed to start container' })
      setDockerLoading(false)
    }
  }

  const handleStopDocker = async () => {
    setDockerLoading(true)
    try {
      await timesketchApi.stopDocker()
      setMessage({ type: 'success', text: 'Container stopped' })
      const res = await timesketchApi.getDockerStatus()
      setDockerStatus(res.data)
    } catch {
      setMessage({ type: 'error', text: 'Failed to stop container' })
    } finally {
      setDockerLoading(false)
    }
  }

  const handleOpenSketch = (sketchId: number) => {
    window.open(`http://localhost:5000/sketch/${sketchId}/`, '_blank')
  }

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="80vh">
        <CircularProgress size={32} />
      </Box>
    )
  }

  const filteredSketches = searchQuery.trim()
    ? sketches.filter(s => s.name.toLowerCase().includes(searchQuery.toLowerCase()) || s.description?.toLowerCase().includes(searchQuery.toLowerCase()))
    : sketches

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={3}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 0.5 }}>Timesketch</Typography>
          <Typography variant="body2" color="text.secondary">Timeline analysis and forensics</Typography>
        </Box>
        <Box display="flex" gap={1}>
          <IconButton size="small" onClick={loadData}><RefreshIcon sx={{ fontSize: 20 }} /></IconButton>
          {status?.connected && (
            <Button size="small" variant="contained" startIcon={<AddIcon />} onClick={() => setCreateDialogOpen(true)}>
              New Sketch
            </Button>
          )}
        </Box>
      </Box>

      {message && (
        <Alert severity={message.type} onClose={() => setMessage(null)} sx={{ mb: 2 }}>
          {message.text}
        </Alert>
      )}

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <StatCard
            title="Server Status"
            value={status?.connected ? 'Connected' : 'Disconnected'}
            subtitle={status?.message || (status?.configured ? 'Configured' : 'Not configured')}
            icon={status?.connected ? <CheckCircleIcon /> : <ErrorIcon />}
            color={status?.connected ? theme.palette.success.main : theme.palette.error.main}
          />
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent sx={{ pb: 1 }}>
              <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.7rem' }}>
                Docker Status
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                {dockerStatus?.docker_available ? (
                  <>
                    <Chip
                      icon={dockerStatus.daemon_running ? <CheckCircleIcon /> : <ErrorIcon />}
                      label={dockerStatus.daemon_running ? 'Docker Running' : 'Docker Stopped'}
                      color={dockerStatus.daemon_running ? 'success' : 'error'}
                      size="small"
                    />
                    <Chip
                      icon={dockerStatus.container_running ? <CheckCircleIcon /> : <ErrorIcon />}
                      label={dockerStatus.container_running ? 'Container Up' : 'Container Down'}
                      color={dockerStatus.container_running ? 'success' : 'default'}
                      size="small"
                    />
                  </>
                ) : (
                  <Chip icon={<ErrorIcon />} label="Docker Not Available" color="error" size="small" />
                )}
              </Box>
            </CardContent>
            {dockerStatus?.docker_available && dockerStatus.daemon_running && (
              <CardActions sx={{ pt: 0 }}>
                <Button size="small" startIcon={<PlayIcon />} onClick={handleStartDocker} disabled={dockerStatus.container_running || dockerLoading}>
                  Start
                </Button>
                <Button size="small" startIcon={<StopIcon />} onClick={handleStopDocker} disabled={!dockerStatus.container_running || dockerLoading}>
                  Stop
                </Button>
              </CardActions>
            )}
          </Card>
        </Grid>
      </Grid>

      {!status?.configured && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          Timesketch is not configured. Go to Settings to configure your connection.
        </Alert>
      )}

      {status?.connected && (
        <Box sx={{ bgcolor: 'background.paper', borderRadius: 3, border: 1, borderColor: 'divider' }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}>
            <Tabs value={currentTab} onChange={(_, v) => setCurrentTab(v)}>
              <Tab label={`Sketches (${sketches.length})`} sx={{ minHeight: 48 }} />
              <Tab label="About" sx={{ minHeight: 48 }} />
            </Tabs>
          </Box>

          <Box sx={{ p: 2 }}>
            <TabPanel value={currentTab} index={0}>
              <Box sx={{ mb: 2, maxWidth: 400 }}>
                <SearchInput value={searchQuery} onChange={setSearchQuery} placeholder="Search sketches..." />
              </Box>

              {sketches.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 6 }}>
                  <TimelineIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                  <Typography color="text.secondary">No sketches found</Typography>
                  <Button size="small" variant="contained" startIcon={<AddIcon />} onClick={() => setCreateDialogOpen(true)} sx={{ mt: 2 }}>
                    Create Sketch
                  </Button>
                </Box>
              ) : filteredSketches.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 6 }}>
                  <Typography color="text.secondary">No sketches match your search</Typography>
                </Box>
              ) : (
                <Grid container spacing={2}>
                  {filteredSketches.map((sketch) => (
                    <Grid item xs={12} sm={6} md={4} key={sketch.id}>
                      <Card variant="outlined">
                        <CardContent sx={{ pb: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{sketch.name}</Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5, minHeight: 32 }}>
                            {sketch.description || 'No description'}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                            Created: {new Date(sketch.created_at).toLocaleDateString()}
                            {sketch.user && ` by ${sketch.user.username}`}
                          </Typography>
                        </CardContent>
                        <CardActions sx={{ pt: 0 }}>
                          <Button size="small" startIcon={<LaunchIcon />} onClick={() => handleOpenSketch(sketch.id)}>
                            Open
                          </Button>
                        </CardActions>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              )}
            </TabPanel>

            <TabPanel value={currentTab} index={1}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>About Timesketch</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Timesketch is an open-source tool for collaborative forensic timeline analysis. It allows
                security analysts to visualize, search, and investigate event timelines from multiple sources.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Features</Typography>
              <Box component="ul" sx={{ m: 0, pl: 2 }}>
                <li><Typography variant="body2" color="text.secondary">Collaborative timeline analysis</Typography></li>
                <li><Typography variant="body2" color="text.secondary">Advanced search and filtering</Typography></li>
                <li><Typography variant="body2" color="text.secondary">Event tagging and commenting</Typography></li>
                <li><Typography variant="body2" color="text.secondary">DeepTempo integration</Typography></li>
              </Box>
            </TabPanel>
          </Box>
        </Box>
      )}

      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ pb: 1 }}>Create New Sketch</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <TextField autoFocus label="Sketch Name" fullWidth value={newSketch.name} onChange={(e) => setNewSketch({ ...newSketch, name: e.target.value })} sx={{ mb: 2 }} />
          <TextField label="Description" fullWidth multiline rows={3} value={newSketch.description} onChange={(e) => setNewSketch({ ...newSketch, description: e.target.value })} />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateSketch} variant="contained">Create</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

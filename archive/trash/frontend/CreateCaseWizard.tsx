import { useState, useEffect } from 'react'
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Stepper,
  Step,
  StepLabel,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Box,
  Typography,
  Grid,
  Card,
  CardActionArea,
  Chip,
  Alert,
  Autocomplete,
} from '@mui/material'
import {
  Description as TemplateIcon,
  Add as CustomIcon,
  Warning as PhishingIcon,
  BugReport as MalwareIcon,
  Security as BreachIcon,
} from '@mui/icons-material'
import { casesApi, caseTemplatesApi } from '../../services/api'

interface CaseTemplate {
  template_id: string
  name: string
  description: string
  default_title: string
  default_description: string
  default_priority: string
  default_status: string
  default_tags: string[]
}

interface CreateCaseWizardProps {
  open: boolean
  onClose: () => void
  onCreated?: () => void
  selectedFindingIds?: string[]
}

const steps = ['Choose Template', 'Case Details', 'Review & Create']

const templateIcons: Record<string, any> = {
  'template-phishing': <PhishingIcon />,
  'template-malware': <MalwareIcon />,
  'template-breach': <BreachIcon />,
}

export default function CreateCaseWizard({
  open,
  onClose,
  onCreated,
  selectedFindingIds = [],
}: CreateCaseWizardProps) {
  const [activeStep, setActiveStep] = useState(0)
  const [templates, setTemplates] = useState<CaseTemplate[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState<CaseTemplate | null>(null)
  const [useCustom, setUseCustom] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  
  const [caseData, setCaseData] = useState({
    title: '',
    description: '',
    priority: 'medium',
    status: 'new',
    tags: [] as string[],
    assignee: '',
  })

  useEffect(() => {
    if (open) {
      loadTemplates()
    }
  }, [open])

  const loadTemplates = async () => {
    try {
      const response = await caseTemplatesApi.getAll()
      setTemplates(response.data.templates || [])
    } catch (error) {
      console.error('Failed to load templates:', error)
    }
  }

  const handleTemplateSelect = (template: CaseTemplate | null) => {
    setSelectedTemplate(template)
    setUseCustom(false)
    if (template) {
      setCaseData({
        title: template.default_title,
        description: template.default_description,
        priority: template.default_priority,
        status: template.default_status,
        tags: template.default_tags,
        assignee: '',
      })
    }
  }

  const handleCustomSelect = () => {
    setUseCustom(true)
    setSelectedTemplate(null)
    setCaseData({
      title: '',
      description: '',
      priority: 'medium',
      status: 'new',
      tags: [],
      assignee: '',
    })
  }

  const handleNext = () => {
    if (activeStep === 0 && !selectedTemplate && !useCustom) {
      setError('Please select a template or choose custom case')
      return
    }
    if (activeStep === 1 && !caseData.title.trim()) {
      setError('Please enter a case title')
      return
    }
    setError('')
    setActiveStep((prev) => prev + 1)
  }

  const handleBack = () => {
    setActiveStep((prev) => prev - 1)
    setError('')
  }

  const handleCreate = async () => {
    setLoading(true)
    setError('')
    try {
      if (selectedTemplate) {
        // Use template to create case
        await caseTemplatesApi.createFromTemplate(selectedTemplate.template_id, {
          ...caseData,
          finding_ids: selectedFindingIds,
        })
      } else {
        // Create custom case
        await casesApi.create({
          ...caseData,
          finding_ids: selectedFindingIds,
        })
      }
      handleClose()
      if (onCreated) onCreated()
    } catch (err: any) {
      console.error('Failed to create case:', err)
      setError(err.response?.data?.detail || 'Failed to create case')
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    setActiveStep(0)
    setSelectedTemplate(null)
    setUseCustom(false)
    setCaseData({
      title: '',
      description: '',
      priority: 'medium',
      status: 'new',
      tags: [],
      assignee: '',
    })
    setError('')
    onClose()
  }

  const getPriorityColor = (priority: string) => {
    const colors: Record<string, any> = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'success',
    }
    return colors[priority] || 'default'
  }

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Typography variant="h5" fontWeight="bold">
          Create New Case
        </Typography>
        <Stepper activeStep={activeStep} sx={{ mt: 2 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Step 1: Choose Template */}
        {activeStep === 0 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Choose a template to get started
            </Typography>
            <Grid container spacing={2}>
              {/* Custom Case Option */}
              <Grid item xs={12} sm={6}>
                <Card
                  sx={{
                    border: useCustom ? 2 : 1,
                    borderColor: useCustom ? 'primary.main' : 'divider',
                  }}
                >
                  <CardActionArea onClick={handleCustomSelect} sx={{ p: 2 }}>
                    <Box display="flex" alignItems="center" gap={2}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: 'grey.200',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        <CustomIcon />
                      </Box>
                      <Box flex={1}>
                        <Typography variant="subtitle1" fontWeight="bold">
                          Custom Case
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Start from scratch
                        </Typography>
                      </Box>
                    </Box>
                  </CardActionArea>
                </Card>
              </Grid>

              {/* Template Options */}
              {templates.map((template) => (
                <Grid item xs={12} sm={6} key={template.template_id}>
                  <Card
                    sx={{
                      border: selectedTemplate?.template_id === template.template_id ? 2 : 1,
                      borderColor:
                        selectedTemplate?.template_id === template.template_id
                          ? 'primary.main'
                          : 'divider',
                    }}
                  >
                    <CardActionArea
                      onClick={() => handleTemplateSelect(template)}
                      sx={{ p: 2 }}
                    >
                      <Box display="flex" alignItems="center" gap={2}>
                        <Box
                          sx={{
                            width: 48,
                            height: 48,
                            borderRadius: 2,
                            bgcolor: 'primary.light',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'primary.main',
                          }}
                        >
                          {templateIcons[template.template_id] || <TemplateIcon />}
                        </Box>
                        <Box flex={1}>
                          <Typography variant="subtitle1" fontWeight="bold">
                            {template.name}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {template.description}
                          </Typography>
                          <Box mt={1}>
                            <Chip
                              label={template.default_priority}
                              size="small"
                              color={getPriorityColor(template.default_priority)}
                            />
                          </Box>
                        </Box>
                      </Box>
                    </CardActionArea>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        {/* Step 2: Case Details */}
        {activeStep === 1 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Enter case details
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Title"
                  value={caseData.title}
                  onChange={(e) => setCaseData({ ...caseData, title: e.target.value })}
                  required
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={4}
                  label="Description"
                  value={caseData.description}
                  onChange={(e) => setCaseData({ ...caseData, description: e.target.value })}
                />
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Priority</InputLabel>
                  <Select
                    value={caseData.priority}
                    label="Priority"
                    onChange={(e) => setCaseData({ ...caseData, priority: e.target.value })}
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={caseData.status}
                    label="Status"
                    onChange={(e) => setCaseData({ ...caseData, status: e.target.value })}
                  >
                    <MenuItem value="new">New</MenuItem>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="in-progress">In Progress</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Assignee"
                  value={caseData.assignee}
                  onChange={(e) => setCaseData({ ...caseData, assignee: e.target.value })}
                  placeholder="SOC Analyst"
                />
              </Grid>
              <Grid item xs={12}>
                <Autocomplete
                  multiple
                  freeSolo
                  options={[]}
                  value={caseData.tags}
                  onChange={(_, value) => setCaseData({ ...caseData, tags: value })}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip label={option} {...getTagProps({ index })} />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField {...params} label="Tags" placeholder="Add tags..." />
                  )}
                />
              </Grid>
            </Grid>
          </Box>
        )}

        {/* Step 3: Review */}
        {activeStep === 2 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review case details
            </Typography>
            <Card sx={{ p: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Template
                  </Typography>
                  <Typography variant="body1">
                    {selectedTemplate ? selectedTemplate.name : 'Custom Case'}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Title
                  </Typography>
                  <Typography variant="body1">{caseData.title}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Description
                  </Typography>
                  <Typography variant="body1">{caseData.description || 'N/A'}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Priority
                  </Typography>
                  <Chip
                    label={caseData.priority}
                    color={getPriorityColor(caseData.priority)}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Status
                  </Typography>
                  <Chip label={caseData.status} size="small" color="primary" />
                </Grid>
                {caseData.assignee && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Assignee
                    </Typography>
                    <Typography variant="body1">{caseData.assignee}</Typography>
                  </Grid>
                )}
                {caseData.tags.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Tags
                    </Typography>
                    <Box display="flex" gap={1} mt={1}>
                      {caseData.tags.map((tag) => (
                        <Chip key={tag} label={tag} size="small" />
                      ))}
                    </Box>
                  </Grid>
                )}
                {selectedFindingIds.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Associated Findings
                    </Typography>
                    <Typography variant="body2">
                      {selectedFindingIds.length} finding(s) will be linked
                    </Typography>
                  </Grid>
                )}
              </Grid>
            </Card>
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        {activeStep > 0 && (
          <Button onClick={handleBack} disabled={loading}>
            Back
          </Button>
        )}
        {activeStep < steps.length - 1 ? (
          <Button variant="contained" onClick={handleNext}>
            Next
          </Button>
        ) : (
          <Button variant="contained" onClick={handleCreate} disabled={loading}>
            {loading ? 'Creating...' : 'Create Case'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}


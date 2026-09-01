export class NotificationService {
  private static instance: NotificationService
  private isEnabled: boolean = true
  private permissionGranted: boolean = false

  private constructor() {
    this.checkPermission()
  }

  public static getInstance(): NotificationService {
    if (!NotificationService.instance) {
      NotificationService.instance = new NotificationService()
    }
    return NotificationService.instance
  }

  public isSupported(): boolean {
    return 'Notification' in window
  }

  private checkPermission(): void {
    if (this.isSupported()) {
      this.permissionGranted = Notification.permission === 'granted'
    }
  }

  public async requestPermission(): Promise<boolean> {
    if (!this.isSupported()) {
      console.warn('Browser does not support notifications')
      return false
    }

    if (Notification.permission === 'granted') {
      this.permissionGranted = true
      return true
    }

    if (Notification.permission === 'denied') {
      console.warn('Notification permission was denied by user')
      return false
    }

    try {
      const permission = await Notification.requestPermission()
      this.permissionGranted = permission === 'granted'
      return this.permissionGranted
    } catch (error) {
      console.error('Error requesting notification permission:', error)
      return false
    }
  }

  public setEnabled(enabled: boolean): void {
    this.isEnabled = enabled
  }

  public async show(
    title: string,
    options?: {
      body?: string
      icon?: string
      tag?: string
      requireInteraction?: boolean
      silent?: boolean
      data?: any
      onClick?: () => void
    }
  ): Promise<void> {
    if (!this.isEnabled) {
      return
    }

    if (!this.isSupported()) {
      console.warn('Browser does not support notifications')
      return
    }

    if (!this.permissionGranted) {
      const granted = await this.requestPermission()
      if (!granted) {
        return
      }
    }

    try {
      const notification = new Notification(title, {
        body: options?.body,
        icon: options?.icon || '/favicon.ico',
        tag: options?.tag,
        requireInteraction: options?.requireInteraction || false,
        silent: options?.silent || false,
        data: options?.data,
      })

      if (options?.onClick) {
        notification.onclick = () => {
          window.focus()
          options.onClick?.()
          notification.close()
        }
      }

      if (!options?.requireInteraction) {
        setTimeout(() => notification.close(), 10000)
      }
    } catch (error) {
      console.error('Error showing notification:', error)
    }
  }

  public notifyNewFinding(finding: {
    finding_id: string
    title?: string
    severity?: string
    description?: string
  }): void {
    this.show('New Security Finding', {
      body: `${finding.severity?.toUpperCase() || 'UNKNOWN'}: ${finding.title || finding.description || finding.finding_id}`,
      tag: `finding-${finding.finding_id}`,
      requireInteraction: finding.severity === 'critical' || finding.severity === 'high',
      data: { type: 'finding', id: finding.finding_id },
    })
  }

  public notifyCaseUpdate(caseInfo: {
    case_id: string
    title: string
    status?: string
    priority?: string
    message?: string
  }): void {
    const body = caseInfo.message || `Case status: ${caseInfo.status || 'updated'}`
    const requireInteraction = caseInfo.priority === 'critical' || caseInfo.priority === 'high'

    this.show(`Case Updated: ${caseInfo.title}`, {
      body,
      tag: `case-${caseInfo.case_id}`,
      requireInteraction,
      data: { type: 'case', id: caseInfo.case_id },
    })
  }

  public notifyInvestigationComplete(investigation: {
    finding_id?: string
    case_id?: string
    title: string
    summary?: string
  }): void {
    this.show('Investigation Complete', {
      body: `${investigation.title}${investigation.summary ? ': ' + investigation.summary : ''}`,
      tag: `investigation-${investigation.finding_id || investigation.case_id}`,
      requireInteraction: true,
      data: {
        type: 'investigation',
        finding_id: investigation.finding_id,
        case_id: investigation.case_id,
      },
    })
  }

  public notifyMcpServerStatus(server: {
    name: string
    status: string
    error?: string
  }): void {
    const isError = server.status === 'error' || server.status === 'stopped'
    this.show(`MCP Server: ${server.name}`, {
      body: server.error || `Status: ${server.status}`,
      tag: `mcp-${server.name}`,
      requireInteraction: isError,
      data: { type: 'mcp', server: server.name },
    })
  }

  public notifyGeneric(
    title: string,
    message: string,
    options?: {
      severity?: 'info' | 'success' | 'warning' | 'error'
      requireInteraction?: boolean
      tag?: string
    }
  ): void {
    this.show(title, {
      body: message,
      tag: options?.tag,
      requireInteraction: options?.requireInteraction || options?.severity === 'error',
      data: { type: 'generic', severity: options?.severity },
    })
  }
}

export const notificationService = NotificationService.getInstance()


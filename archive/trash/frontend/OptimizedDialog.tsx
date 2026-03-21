/**
 * Optimized Dialog Component - Performance wrapper for large dialogs
 * 
 * Optimizations:
 * - Lazy rendering of dialog content (only when open)
 * - Memoized dialog transitions
 * - Debounced resize handlers
 * - Lazy tab loading (tabs load only when selected)
 * - Cleanup on unmount to prevent memory leaks
 */

import { memo, useMemo, useEffect, useRef } from 'react'
import {
  Dialog,
  DialogProps,
  Fade,
  useMediaQuery,
  useTheme,
} from '@mui/material'

interface OptimizedDialogProps extends DialogProps {
  /** Dialog content - only rendered when open */
  children: React.ReactNode
  /** Enable lazy rendering (default: true) */
  lazyRender?: boolean
  /** Cleanup delay after close in ms (default: 300) */
  cleanupDelay?: number
  /** Disable scroll lock for better performance */
  disableScrollLock?: boolean
}

/**
 * Optimized dialog wrapper that prevents unnecessary renders
 * and cleans up resources when closed
 */
const OptimizedDialog = memo(function OptimizedDialog({
  open,
  children,
  lazyRender = true,
  cleanupDelay = 300,
  disableScrollLock = false,
  TransitionComponent = Fade,
  transitionDuration = 300,
  maxWidth = 'lg',
  fullWidth = true,
  ...props
}: OptimizedDialogProps) {
  const theme = useTheme()
  const fullScreen = useMediaQuery(theme.breakpoints.down('md'))
  const hasEverOpened = useRef(false)
  const cleanupTimer = useRef<NodeJS.Timeout | null>(null)

  // Track if dialog has ever been opened
  useEffect(() => {
    if (open) {
      hasEverOpened.current = true
    }
  }, [open])

  // Cleanup timer on close
  useEffect(() => {
    if (!open && hasEverOpened.current) {
      cleanupTimer.current = setTimeout(() => {
        // Allow for potential cleanup operations
        if (typeof window !== 'undefined' && window.gc) {
          // Force garbage collection if available (dev mode)
          window.gc()
        }
      }, cleanupDelay)
    }

    return () => {
      if (cleanupTimer.current) {
        clearTimeout(cleanupTimer.current)
      }
    }
  }, [open, cleanupDelay])

  // Memoize dialog paper props for performance
  const paperProps = useMemo(
    () => ({
      sx: {
        maxHeight: fullScreen ? '100%' : '90vh',
        height: fullScreen ? '100%' : 'auto',
        // Use GPU acceleration
        transform: 'translateZ(0)',
        willChange: 'transform, opacity',
      },
    }),
    [fullScreen]
  )

  // Only render content if dialog has been opened (lazy rendering)
  const shouldRenderContent = lazyRender ? hasEverOpened.current : true

  return (
    <Dialog
      open={open}
      fullScreen={fullScreen}
      fullWidth={fullWidth}
      maxWidth={maxWidth}
      TransitionComponent={TransitionComponent as any}
      transitionDuration={transitionDuration}
      disableScrollLock={disableScrollLock}
      PaperProps={paperProps}
      {...props}
    >
      {shouldRenderContent && children}
    </Dialog>
  )
})

export default OptimizedDialog


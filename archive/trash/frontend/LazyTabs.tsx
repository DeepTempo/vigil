/**
 * Lazy Tabs Component - Performance optimization for tab-heavy dialogs
 * 
 * Optimizations:
 * - Lazy loading: Tabs are only rendered when selected
 * - Keep-alive mode: Previously viewed tabs stay mounted (optional)
 * - Suspense support for async tab content
 * - Memoized tab panels
 */

import { memo, useState, useEffect, useMemo, Suspense } from 'react'
import {
  Tabs,
  Tab,
  Box,
  TabsProps,
  CircularProgress,
  Typography,
} from '@mui/material'

export interface LazyTabConfig {
  label: string
  icon?: React.ReactElement
  content: React.ReactNode
  /** Preload this tab even if not selected */
  preload?: boolean
  /** Keep mounted after first render */
  keepMounted?: boolean
}

interface LazyTabsProps extends Omit<TabsProps, 'children'> {
  tabs: LazyTabConfig[]
  /** Initial tab index */
  defaultTab?: number
  /** Controlled tab value */
  value?: number
  /** Tab change handler */
  onTabChange?: (newValue: number) => void
  /** Keep all visited tabs mounted (default: true) */
  keepMounted?: boolean
  /** Show loading indicator when tab content is suspended */
  showLoading?: boolean
  /** Custom loading component */
  LoadingComponent?: React.ComponentType
}

/**
 * Memoized tab panel that only renders when active or has been visited
 */
const LazyTabPanel = memo(function LazyTabPanel({
  children,
  value,
  index,
  keepMounted,
  hasBeenViewed,
  showLoading,
  LoadingComponent,
}: {
  children: React.ReactNode
  value: number
  index: number
  keepMounted: boolean
  hasBeenViewed: boolean
  showLoading: boolean
  LoadingComponent?: React.ComponentType
}) {
  const isActive = value === index
  const shouldRender = isActive || (keepMounted && hasBeenViewed)

  if (!shouldRender) {
    return null
  }

  const LoadingFallback = LoadingComponent || (() => (
    <Box
      display="flex"
      justifyContent="center"
      alignItems="center"
      minHeight={200}
      flexDirection="column"
      gap={2}
    >
      <CircularProgress />
      <Typography variant="body2" color="text.secondary">
        Loading tab content...
      </Typography>
    </Box>
  ))

  return (
    <div
      role="tabpanel"
      hidden={!isActive}
      id={`tabpanel-${index}`}
      aria-labelledby={`tab-${index}`}
      style={{
        // Keep in DOM but hide visually for keepMounted tabs
        display: isActive ? 'block' : 'none',
        height: isActive ? 'auto' : 0,
        overflow: isActive ? 'visible' : 'hidden',
      }}
    >
      {showLoading ? (
        <Suspense fallback={<LoadingFallback />}>{children}</Suspense>
      ) : (
        children
      )}
    </div>
  )
})

/**
 * Lazy Tabs component that only renders tab content when needed
 */
const LazyTabs = memo(function LazyTabs({
  tabs,
  defaultTab = 0,
  value: controlledValue,
  onTabChange,
  keepMounted = true,
  showLoading = true,
  LoadingComponent,
  ...tabsProps
}: LazyTabsProps) {
  const [internalValue, setInternalValue] = useState(defaultTab)
  const [viewedTabs, setViewedTabs] = useState<Set<number>>(new Set([defaultTab]))

  // Use controlled or uncontrolled value
  const value = controlledValue !== undefined ? controlledValue : internalValue

  // Track which tabs have been viewed
  useEffect(() => {
    setViewedTabs((prev) => new Set(prev).add(value))
  }, [value])

  // Handle tab change
  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    if (controlledValue === undefined) {
      setInternalValue(newValue)
    }
    onTabChange?.(newValue)
  }

  // Memoize tab headers
  const tabHeaders = useMemo(
    () =>
      tabs.map((tab, index) => (
        <Tab
          key={index}
          label={tab.label}
          icon={tab.icon}
          id={`tab-${index}`}
          aria-controls={`tabpanel-${index}`}
        />
      )),
    [tabs]
  )

  // Preload specified tabs
  useEffect(() => {
    const preloadIndices = tabs
      .map((tab, index) => (tab.preload ? index : -1))
      .filter((index) => index !== -1)

    if (preloadIndices.length > 0) {
      setViewedTabs((prev) => {
        const newSet = new Set(prev)
        preloadIndices.forEach((index) => newSet.add(index))
        return newSet
      })
    }
  }, [tabs])

  return (
    <Box sx={{ width: '100%' }}>
      {/* Tab Headers */}
      <Tabs
        value={value}
        onChange={handleTabChange}
        variant="scrollable"
        scrollButtons="auto"
        {...tabsProps}
      >
        {tabHeaders}
      </Tabs>

      {/* Tab Panels */}
      <Box sx={{ mt: 2 }}>
        {tabs.map((tab, index) => {
          const shouldKeepMounted = tab.keepMounted ?? keepMounted
          const hasBeenViewed = viewedTabs.has(index)

          return (
            <LazyTabPanel
              key={index}
              value={value}
              index={index}
              keepMounted={shouldKeepMounted}
              hasBeenViewed={hasBeenViewed}
              showLoading={showLoading}
              LoadingComponent={LoadingComponent}
            >
              {tab.content}
            </LazyTabPanel>
          )
        })}
      </Box>
    </Box>
  )
})

export default LazyTabs


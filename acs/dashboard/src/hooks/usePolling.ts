// src/hooks/usePolling.ts — Polling replacement for useSSE
//
// API Gateway + Lambda cannot hold the long-lived connection that
// Server-Sent Events require, so the dashboard polls the REST endpoints
// on a fixed interval instead. This hook mirrors the useSSE signature
// ({ data, status, reset }) so it's a drop-in replacement in App.tsx.

import { useState, useEffect, useRef, useCallback } from 'react'

type PollStatus = 'connecting' | 'open' | 'error' | 'closed'

export function usePolling<T>(
  fetcher: () => Promise<T>,
  initial: T,
  options: { intervalMs?: number } = {}
): { data: T; status: PollStatus; reset: () => void } {
  const { intervalMs = 4000 } = options
  const [data, setData]       = useState<T>(initial)
  const [status, setStatus]   = useState<PollStatus>('connecting')
  const timerRef              = useRef<ReturnType<typeof setInterval> | null>(null)
  const cancelledRef          = useRef(false)

  const poll = useCallback(async () => {
    try {
      const result = await fetcher()
      if (!cancelledRef.current) {
        setData(result)
        setStatus('open')
      }
    } catch {
      if (!cancelledRef.current) {
        setStatus('error')
      }
    }
  }, [fetcher])

  const start = useCallback(() => {
    cancelledRef.current = false
    setStatus('connecting')
    poll() // fire immediately, don't wait for first interval
    if (timerRef.current) clearInterval(timerRef.current)
    timerRef.current = setInterval(poll, intervalMs)
  }, [poll, intervalMs])

  useEffect(() => {
    start()
    return () => {
      cancelledRef.current = true
      if (timerRef.current) clearInterval(timerRef.current)
      setStatus('closed')
    }
  }, [start])

  const reset = useCallback(() => {
    start()
  }, [start])

  return { data, status, reset }
}

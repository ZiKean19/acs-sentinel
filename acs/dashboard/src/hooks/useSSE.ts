// src/hooks/useSSE.ts — Real-time Server-Sent Events hook
import { useState, useEffect, useRef, useCallback } from 'react'

type SSEStatus = 'connecting' | 'open' | 'error' | 'closed'

export function useSSE<T>(
  url: string,
  initial: T,
  options: { maxItems?: number } = {}
): { data: T; status: SSEStatus; reset: () => void } {
  const { maxItems = 500 }  = options
  const [data, setData]     = useState<T>(initial)
  const [status, setStatus] = useState<SSEStatus>('connecting')
  const esRef               = useRef<EventSource | null>(null)
  const retryRef            = useRef<ReturnType<typeof setTimeout> | null>(null)
  const retryCount          = useRef(0)
  const MAX_RETRY_DELAY     = 30_000

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
    setStatus('connecting')
    const es    = new EventSource(url)
    esRef.current = es

    es.onopen = () => {
      setStatus('open')
      retryCount.current = 0
    }

    es.addEventListener('init', (e: MessageEvent) => {
      try { setData(JSON.parse(e.data)) } catch { /* ignore */ }
    })

    es.addEventListener('update', (e: MessageEvent) => {
      try {
        const item = JSON.parse(e.data)
        setData(prev => {
          if (Array.isArray(prev)) {
            const next = [item, ...prev]
            return (maxItems && next.length > maxItems
              ? next.slice(0, maxItems)
              : next) as unknown as T
          }
          return item as unknown as T
        })
      } catch { /* ignore */ }
    })

    es.addEventListener('replace', (e: MessageEvent) => {
      try { setData(JSON.parse(e.data)) } catch { /* ignore */ }
    })

    es.onerror = () => {
      es.close()
      esRef.current = null
      setStatus('error')
      const delay = Math.min(1000 * 2 ** retryCount.current, MAX_RETRY_DELAY)
      retryCount.current++
      retryRef.current = setTimeout(connect, delay)
    }
  }, [url, maxItems])

  useEffect(() => {
    connect()
    return () => {
      esRef.current?.close()
      esRef.current = null
      if (retryRef.current) clearTimeout(retryRef.current)
      setStatus('closed')
    }
  }, [connect])

  const reset = useCallback(() => {
    retryCount.current = 0
    connect()
  }, [connect])

  return { data, status, reset }
}

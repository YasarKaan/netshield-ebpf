import { useEffect, useRef } from 'react';
import { useStore } from '../store';

const INITIAL_RETRY_DELAY_MS = 1000;
const MAX_RETRY_DELAY_MS = 30000;

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const { wsUrl, token, setWsConnected, updateStats, addBlockEvent } = useStore();

  useEffect(() => {
    let timeoutId: ReturnType<typeof setTimeout>;
    let retryDelay = INITIAL_RETRY_DELAY_MS;
    let isUnmounted = false;

    const connect = () => {
      if (isUnmounted) {
        return;
      }

      const urlWithToken = `${wsUrl}?token=${encodeURIComponent(token)}`;
      const ws = new WebSocket(urlWithToken);
      wsRef.current = ws;

      ws.onopen = () => {
        retryDelay = INITIAL_RETRY_DELAY_MS;
        setWsConnected(true);
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          switch (msg.type) {
            case 'block_event':
              addBlockEvent(msg);
              break;
            case 'stats_update':
              updateStats(msg);
              break;
            default:
              break;
          }
        } catch (err) {
          console.error('Error parsing WebSocket message:', err);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        if (isUnmounted) {
          return;
        }
        timeoutId = setTimeout(() => {
          retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS);
          connect();
        }, retryDelay);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      isUnmounted = true;
      clearTimeout(timeoutId);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [wsUrl, token, setWsConnected, updateStats, addBlockEvent]);
}

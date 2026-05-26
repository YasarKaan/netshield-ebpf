import { create } from 'zustand';

export interface BlockEntry {
  ip: string;
  reason: string;
  blocked_at: string;
  detail: string;
  country?: string;
  lat?: number;
  lon?: number;
}

export interface StatsUpdate {
  total_packets: number;
  dropped_packets: number;
  active_blocks: number;
  pps_current: number;
}

export interface BlockEvent {
  ip: string;
  reason: string;
  detail: string;
  country: string;
  lat: number;
  lon: number;
  ts: string;
}

interface AppState {
  wsConnected: boolean;
  totalPackets: number;
  droppedPackets: number;
  activeBlocks: number;
  ppsCurrent: number;
  ppsHistory: { ts: number; pps: number }[];
  blockedIPs: BlockEntry[];
  events: BlockEntry[];
  token: string;
  apiUrl: string;
  wsUrl: string;
  setToken: (token: string) => void;
  setWsConnected: (connected: boolean) => void;
  updateStats: (stats: StatsUpdate) => void;
  addBlockEvent: (event: BlockEvent) => void;
  setBlockedIPs: (entries: BlockEntry[]) => void;
  setEvents: (events: BlockEntry[]) => void;
}

export const useStore = create<AppState>((set) => {
  const initialToken = localStorage.getItem('ns_token') || '';
  const host = window.location.hostname;
  const proto = window.location.protocol === 'https:' ? 'https' : 'http';
  const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const initialApiUrl = import.meta.env.VITE_API_URL || `${proto}://${host}:8080`;
  const initialWsUrl = import.meta.env.VITE_WS_URL || `${wsProto}://${host}:8080/ws`;

  return {
    wsConnected: false,
    totalPackets: 0,
    droppedPackets: 0,
    activeBlocks: 0,
    ppsCurrent: 0,
    ppsHistory: [],
    blockedIPs: [],
    events: [],
    token: initialToken,
    apiUrl: initialApiUrl,
    wsUrl: initialWsUrl,

    setToken: (token) => {
      localStorage.setItem('ns_token', token);
      set({ token });
    },

    setWsConnected: (wsConnected) => set({ wsConnected }),

    updateStats: (stats) => set((state) => {
      const now = Date.now();
      const newHistory = [...state.ppsHistory, { ts: now, pps: stats.pps_current }];
      if (newHistory.length > 60) {
        newHistory.shift();
      }
      return {
        totalPackets: stats.total_packets,
        droppedPackets: stats.dropped_packets,
        activeBlocks: stats.active_blocks,
        ppsCurrent: stats.pps_current,
        ppsHistory: newHistory,
      };
    }),

    addBlockEvent: (event) => set((state) => {
      const newEntry: BlockEntry = {
        ip: event.ip,
        reason: event.reason,
        blocked_at: event.ts,
        detail: event.detail,
        country: event.country,
        lat: event.lat,
        lon: event.lon,
      };
      
      const newEvents = [newEntry, ...state.events];
      if (newEvents.length > 500) {
        newEvents.pop();
      }

      const newBlocked = [newEntry, ...state.blockedIPs.filter(e => e.ip !== event.ip)];

      return {
        events: newEvents,
        blockedIPs: newBlocked,
        activeBlocks: newBlocked.length,
      };
    }),

    setBlockedIPs: (blockedIPs) => set({ blockedIPs, activeBlocks: blockedIPs.length }),
    setEvents: (events) => set({ events }),
  };
});

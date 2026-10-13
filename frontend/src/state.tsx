import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, hasToken, setToken, setUnauthorizedHandler } from "./api";
import type { SessionDetail, User } from "./types";

// ----------------------------------------------------------------------------- auth

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, displayName: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(hasToken());

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    if (hasToken()) {
      api
        .get<User>("/api/auth/me")
        .then(setUser)
        .catch(() => setUser(null))
        .finally(() => setLoading(false));
    }
  }, []);

  const value = useMemo<AuthCtx>(
    () => ({
      user,
      loading,
      login: async (username, password) => {
        const r = await api.post<{ token: string; user: User }>("/api/auth/login", { username, password });
        setToken(r.token);
        setUser(r.user);
      },
      register: async (username, display_name, password) => {
        const r = await api.post<{ token: string; user: User }>("/api/auth/register", { username, display_name, password });
        setToken(r.token);
        setUser(r.user);
      },
      logout: async () => {
        try {
          await api.post("/api/auth/logout");
        } finally {
          setToken(null);
          setUser(null);
        }
      },
    }),
    [user, loading],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const c = useContext(AuthContext);
  if (!c) throw new Error("AuthProvider missing");
  return c;
}

// ----------------------------------------------------------------------------- active scenario session

interface SessionCtx {
  sessionId: number | null;
  session: SessionDetail | null;
  setSessionId: (id: number | null) => void;
  refresh: () => Promise<void>;
  error: string | null;
  canWrite: boolean;
}

const SessionContext = createContext<SessionCtx | null>(null);
const SESSION_KEY = "threatready.activeSession";

function readStoredSession(): number | null {
  try {
    const v = localStorage.getItem(SESSION_KEY);
    return v ? Number(v) : null;
  } catch {
    return null;
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [sessionId, setSessionIdState] = useState<number | null>(readStoredSession);
  const [session, setSession] = useState<SessionDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const setSessionId = useCallback((id: number | null) => {
    setSessionIdState(id);
    try {
      if (id) localStorage.setItem(SESSION_KEY, String(id));
      else localStorage.removeItem(SESSION_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!sessionId || !user) {
      setSession(null);
      return;
    }
    try {
      setSession(await api.get<SessionDetail>(`/api/sessions/${sessionId}`));
      setError(null);
    } catch (e) {
      setSession(null);
      setError(e instanceof Error ? e.message : String(e));
      setSessionId(null);
    }
  }, [sessionId, user, setSessionId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const canWrite = !!session && !!user && session.user_id === user.id && session.status === "ACTIVE";
  return (
    <SessionContext.Provider value={{ sessionId, session, setSessionId, refresh, error, canWrite }}>{children}</SessionContext.Provider>
  );
}

export function useSession() {
  const c = useContext(SessionContext);
  if (!c) throw new Error("SessionProvider missing");
  return c;
}

// ----------------------------------------------------------------------------- data loading hook

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const depsKey = JSON.stringify(deps);
  const lastKey = useRef<string | null>(null);
  useEffect(() => {
    let alive = true;
    // `loading` means "no data for these inputs yet". A plain reload keeps the current data on screen,
    // so forms are not unmounted (and user input lost) while refreshing.
    if (lastKey.current !== depsKey) setLoading(true);
    lastKey.current = depsKey;
    fn()
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1), setData };
}

import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../state/auth";
import type { FilmOut, AdminSettingsOut } from "../types/dto";
import { ApiError } from "../api/client";
import { getAdminSettings, updateAdminSettings } from "../api/admin";
import { createFilm, listFilms, updateFilmTime } from "../api/cinema";
import { listPerfSummary } from "../api/perf";
import {
  CACHE_LEVELS,
  PerfSummaryBadge,
  PerfSummaryMatrix,
  buildPerfSummary,
  buildPerfSummaryGrid,
  type PerfSummaryGrid,
  type PerfSummaryMap,
} from "../components/PerfSummary";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Films() {
  const auth = useAuth();
  const token = auth.token!;

  const [items, setItems] = useState<FilmOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [perfSummary, setPerfSummary] = useState<PerfSummaryMap | null>(null);
  const [perfSummaryGrid, setPerfSummaryGrid] = useState<PerfSummaryGrid | null>(null);
  const [adminSettings, setAdminSettings] = useState<AdminSettingsOut | null>(null);
  const [pendingSettings, setPendingSettings] = useState<AdminSettingsOut | null>(null);

  const [title, setTitle] = useState("Interstellar");
  const [timeElapsed, setTimeElapsed] = useState<number>(0);

  const [editFilmId, setEditFilmId] = useState<string>("");
  const [editTime, setEditTime] = useState<number>(120);

  const [testRps, setTestRps] = useState<number>(2);
  const [testDuration, setTestDuration] = useState<number>(10);
  const [testStep, setTestStep] = useState<number>(120);
  const [testMode, setTestMode] = useState<"read" | "update_time">("update_time");
  const [running, setRunning] = useState(false);
  const [testCount, setTestCount] = useState(0);
  const [testErrors, setTestErrors] = useState(0);
  const runningRef = useRef(false);
  const [suiteRunning, setSuiteRunning] = useState(false);
  const [suiteStatus, setSuiteStatus] = useState<string | null>(null);
  const [suiteIndex, setSuiteIndex] = useState(0);
  const [suiteTotal, setSuiteTotal] = useState(0);
  const [suiteCount, setSuiteCount] = useState(0);
  const [suiteErrors, setSuiteErrors] = useState(0);
  const [suiteDcsOn, setSuiteDcsOn] = useState(true);
  const [suiteDcsOff, setSuiteDcsOff] = useState(true);
  const [suiteLevels, setSuiteLevels] = useState<boolean[]>(CACHE_LEVELS.map(() => true));
  const suiteCancelRef = useRef(false);

  async function refresh() {
    setError(null);
    setLoading(true);
    try {
      const data = await listFilms(token);
      setItems(data);
      if (!editFilmId && data.length) setEditFilmId(data[0].id);
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
    await refreshPerfCurrent();
    await refreshPerfAll();
  }

  async function refreshSettings() {
    if (auth.role !== "admin") return;
    try {
      const data = await getAdminSettings(token);
      setAdminSettings(data);
      setPendingSettings(data);
      await refreshPerfCurrent(data.cache_level);
      await refreshPerfAll();
    } catch {
      setAdminSettings(null);
      setPendingSettings(null);
    }
  }

  async function refreshPerfCurrent(cacheLevelOverride?: number) {
    if (auth.role !== "admin") return;
    try {
      const cacheLevel = typeof cacheLevelOverride === "number" ? cacheLevelOverride : adminSettings?.cache_level;
      const rows = await listPerfSummary(
        token,
        typeof cacheLevel === "number" ? { cache_level: cacheLevel } : {}
      );
      setPerfSummary(buildPerfSummary(rows));
    } catch {
      setPerfSummary(null);
    }
  }

  async function refreshPerfAll() {
    if (auth.role !== "admin") return;
    try {
      const rows = await listPerfSummary(token, { all_cache_levels: true });
      setPerfSummaryGrid(buildPerfSummaryGrid(rows));
    } catch {
      setPerfSummaryGrid(null);
    }
  }

  useEffect(() => { refresh(); refreshSettings(); }, [auth.role, token]);
  useEffect(() => () => { runningRef.current = false; suiteCancelRef.current = true; }, []);

  async function onCreate() {
    setError(null);
    setLoading(true);
    try {
      await createFilm(token, { title, time_elapsed: timeElapsed });
      await refresh();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  async function onUpdate() {
    if (!editFilmId) return;
    setError(null);
    setLoading(true);
    try {
      await updateFilmTime(token, editFilmId, editTime);
      await refresh();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  async function applySettings() {
    if (!pendingSettings) return;
    setError(null);
    try {
      const updated = await updateAdminSettings(token, pendingSettings);
      setAdminSettings(updated);
      setPendingSettings(updated);
      await refreshPerfCurrent(updated.cache_level);
      await refreshPerfAll();
    } catch (e) {
      setError(toMsg(e));
    }
  }

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  async function runLoadTestOnce({
    mode,
    rps,
    durationSec,
    stepSec,
    filmId,
    shouldStop,
    onSuccess,
    onError,
  }: {
    mode: "read" | "update_time";
    rps: number;
    durationSec: number;
    stepSec: number;
    filmId?: string;
    shouldStop: () => boolean;
    onSuccess?: () => void;
    onError?: () => void;
  }) {
    if (rps <= 0 || durationSec <= 0) return;
    const intervalMs = Math.max(1, Math.floor(1000 / rps));
    const endAt = Date.now() + durationSec * 1000;
    let nextTime = Date.now();
    let localTime = editTime;

    while (!shouldStop() && Date.now() < endAt) {
      nextTime += intervalMs;
      try {
        if (mode === "read") {
          await listFilms(token);
        } else {
          if (!filmId) throw new Error("Missing film id");
          localTime += stepSec;
          await updateFilmTime(token, filmId, localTime);
        }
        onSuccess?.();
      } catch {
        onError?.();
      }
      const delay = nextTime - Date.now();
      if (delay > 0) await sleep(delay);
    }
  }

  function buildSuiteScenarios() {
    const levels = CACHE_LEVELS.filter((level) => suiteLevels[level]);
    const modes: Array<"on" | "off"> = [];
    if (suiteDcsOn) modes.push("on");
    if (suiteDcsOff) modes.push("off");
    return modes.flatMap((mode) =>
      levels.map((level) => ({ dcs_mode: mode, cache_level: level }))
    );
  }

  async function startLoadTest() {
    if (runningRef.current || suiteRunning) return;
    if (testRps <= 0 || testDuration <= 0) return;
    if (testMode === "update_time" && !editFilmId) return;

    runningRef.current = true;
    setRunning(true);
    setTestCount(0);
    setTestErrors(0);

    await runLoadTestOnce({
      mode: testMode,
      rps: testRps,
      durationSec: testDuration,
      stepSec: testStep,
      filmId: editFilmId,
      shouldStop: () => !runningRef.current,
      onSuccess: () => setTestCount((c) => c + 1),
      onError: () => setTestErrors((e) => e + 1),
    });

    runningRef.current = false;
    setRunning(false);
    await refresh();
  }

  function stopLoadTest() {
    runningRef.current = false;
    setRunning(false);
  }

  async function startProfilingSuite() {
    if (suiteRunning || runningRef.current) return;
    if (auth.role !== "admin") return;
    if (testRps <= 0 || testDuration <= 0) {
      setError("Set a positive req/s and duration before running the suite.");
      return;
    }
    if (testMode === "update_time" && !editFilmId) {
      setError("Select a film before running update_time tests.");
      return;
    }
    const scenarios = buildSuiteScenarios();
    if (!scenarios.length) {
      setSuiteStatus("Select at least one scenario.");
      return;
    }

    suiteCancelRef.current = false;
    setSuiteRunning(true);
    setSuiteStatus("Starting...");
    setSuiteIndex(0);
    setSuiteTotal(scenarios.length);
    setSuiteCount(0);
    setSuiteErrors(0);

    for (let i = 0; i < scenarios.length; i += 1) {
      if (suiteCancelRef.current) break;
      const scenario = scenarios[i];
      setSuiteIndex(i + 1);
      setSuiteStatus(`DCS ${scenario.dcs_mode} / L${scenario.cache_level}`);
      try {
        const updated = await updateAdminSettings(token, scenario);
        setAdminSettings(updated);
        setPendingSettings(updated);
      } catch (e) {
        setSuiteErrors((c) => c + 1);
        setError(toMsg(e));
        break;
      }

      await runLoadTestOnce({
        mode: testMode,
        rps: testRps,
        durationSec: testDuration,
        stepSec: testStep,
        filmId: editFilmId,
        shouldStop: () => suiteCancelRef.current,
        onSuccess: () => setSuiteCount((c) => c + 1),
        onError: () => setSuiteErrors((e) => e + 1),
      });
    }

    setSuiteRunning(false);
    setSuiteStatus(suiteCancelRef.current ? "Stopped" : "Done");
    suiteCancelRef.current = false;
    await refresh();
  }

  function stopProfilingSuite() {
    suiteCancelRef.current = true;
    setSuiteStatus("Stopping...");
  }

  return (
    <div className="container">
      <div className="grid cols-2">
        <Card
          title="Films"
          subtitle="time_elapsed is stored encrypted. PDP decides whether to decrypt or mask it."
          right={
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Pill>{auth.role}</Pill>
              {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.read" /> : null}
            </div>
          }
        >
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Button onClick={refresh} disabled={loading}>Refresh</Button>
            <span className="badge">
              <span className="muted">Expected</span>
              <strong>admin/agent</strong> decrypt, <strong>developer</strong> masked
            </span>
          </div>

          {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

          <div style={{ marginTop: 12 }} className="tablewrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>time_elapsed</th>
                </tr>
              </thead>
              <tbody>
                {loading && !items.length ? (
                  <tr><td colSpan={3}><SkeletonRow /></td></tr>
                ) : null}
                {items.map((f) => (
                  <tr key={f.id}>
                    <td className="mono muted">{f.id}</td>
                    <td>{f.title}</td>
                    <td><Mono>{String(f.time_elapsed)}</Mono></td>
                  </tr>
                ))}
                {!loading && !items.length ? (
                  <tr><td colSpan={3} className="muted">No films yet.</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="grid" style={{ gap: 14 }}>
          <Card
            title="Admin controls"
            subtitle="Change DCS mode and cache level for quick experiments."
            right={<Pill kind={auth.role === "admin" ? "ok" : "danger"}>{auth.role}</Pill>}
          >
            {auth.role !== "admin" ? (
              <Alert kind="error">Admin only.</Alert>
            ) : (
              <>
                <div className="grid cols-2">
                  <div className="field">
                    <label>DCS mode</label>
                    <select
                      value={pendingSettings?.dcs_mode ?? "on"}
                      onChange={(e) =>
                        setPendingSettings((s) => s ? { ...s, dcs_mode: e.target.value as "on" | "off" } : s)
                      }
                    >
                      <option value="on">on</option>
                      <option value="off">off</option>
                    </select>
                  </div>
                  <div className="field">
                    <label>Cache level</label>
                    <select
                      value={pendingSettings?.cache_level ?? 0}
                      onChange={(e) =>
                        setPendingSettings((s) => s ? { ...s, cache_level: Number(e.target.value) } : s)
                      }
                    >
                      <option value={0}>L0</option>
                      <option value={1}>L1</option>
                      <option value={2}>L2</option>
                      <option value={3}>L3</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
                  <Button variant="primary" disabled={!pendingSettings || suiteRunning} onClick={applySettings}>Apply</Button>
                  <Button variant="ghost" onClick={refreshSettings}>Refresh</Button>
                </div>
              </>
            )}
          </Card>

          <Card title="Load test" subtitle="Automate read/update_time at N req/s.">
            <div className="grid cols-2">
              <div className="field">
                <label>Mode</label>
                <select value={testMode} onChange={(e) => setTestMode(e.target.value as "read" | "update_time")}>
                  <option value="read">film.read</option>
                  <option value="update_time">film.update_time</option>
                </select>
              </div>
              <div className="field">
                <label>Req/s</label>
                <input type="number" min={1} value={testRps} onChange={(e) => setTestRps(Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Duration (s)</label>
                <input type="number" min={1} value={testDuration} onChange={(e) => setTestDuration(Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Step (sec)</label>
                <input type="number" min={1} value={testStep} onChange={(e) => setTestStep(Number(e.target.value))} />
              </div>
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <Button
                variant="primary"
                disabled={running || suiteRunning || (testMode === "update_time" && !editFilmId)}
                onClick={startLoadTest}
              >
                Start
              </Button>
              <Button variant="ghost" disabled={!running} onClick={stopLoadTest}>
                Stop
              </Button>
              <span className="badge">
                <span className="muted">sent</span>
                <strong>{testCount}</strong>
              </span>
              <span className="badge">
                <span className="muted">errors</span>
                <strong>{testErrors}</strong>
              </span>
            </div>
          </Card>

          <Card title="Profiling suite" subtitle="Run automated scenarios across DCS/cache levels.">
            {auth.role !== "admin" ? (
              <Alert kind="error">Admin only.</Alert>
            ) : (
              <>
                <div className="grid cols-2">
                  <div className="field">
                    <label>DCS modes</label>
                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                      <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={suiteDcsOn}
                          onChange={(e) => setSuiteDcsOn(e.target.checked)}
                          disabled={suiteRunning}
                        />
                        on
                      </label>
                      <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={suiteDcsOff}
                          onChange={(e) => setSuiteDcsOff(e.target.checked)}
                          disabled={suiteRunning}
                        />
                        off
                      </label>
                    </div>
                  </div>
                  <div className="field">
                    <label>Cache levels</label>
                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                      {CACHE_LEVELS.map((level) => (
                        <label key={level} style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <input
                            type="checkbox"
                            checked={suiteLevels[level]}
                            onChange={(e) =>
                              setSuiteLevels((prev) => {
                                const next = [...prev];
                                next[level] = e.target.checked;
                                return next;
                              })
                            }
                            disabled={suiteRunning}
                          />
                          L{level}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <Button
                    variant="primary"
                    disabled={
                      suiteRunning ||
                      running ||
                      (!suiteDcsOn && !suiteDcsOff) ||
                      !suiteLevels.some(Boolean) ||
                      (testMode === "update_time" && !editFilmId)
                    }
                    onClick={startProfilingSuite}
                  >
                    Start
                  </Button>
                  <Button variant="ghost" disabled={!suiteRunning} onClick={stopProfilingSuite}>
                    Stop
                  </Button>
                  <span className="badge">
                    <span className="muted">scenario</span>
                    <strong>{suiteTotal ? `${suiteIndex}/${suiteTotal}` : "--"}</strong>
                  </span>
                  <span className="badge">
                    <span className="muted">sent</span>
                    <strong>{suiteCount}</strong>
                  </span>
                  <span className="badge">
                    <span className="muted">errors</span>
                    <strong>{suiteErrors}</strong>
                  </span>
                  {suiteStatus ? (
                    <span className="badge">
                      <span className="muted">status</span>
                      <strong>{suiteStatus}</strong>
                    </span>
                  ) : null}
                </div>
              </>
            )}
          </Card>

          <Card title="Perf summary" subtitle="Avg total ms by DCS mode and cache level.">
            {auth.role !== "admin" ? (
              <Alert kind="error">Admin only.</Alert>
            ) : (
              <div className="grid" style={{ gap: 12 }}>
                <div>
                  <div className="muted" style={{ marginBottom: 6 }}>film.read</div>
                  <PerfSummaryMatrix grid={perfSummaryGrid} action="film.read" />
                </div>
                <div>
                  <div className="muted" style={{ marginBottom: 6 }}>film.update_time</div>
                  <PerfSummaryMatrix grid={perfSummaryGrid} action="film.update_time" />
                </div>
              </div>
            )}
          </Card>

          <Card
            title="Create film"
            subtitle="Write is allowed for agent/admin. Developer should get 403."
            right={auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.create" /> : null}
          >
            <div className="field">
              <label>Title</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="field">
              <label>Initial time_elapsed (seconds)</label>
              <input type="number" value={timeElapsed} onChange={(e) => setTimeElapsed(Number(e.target.value))} />
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <Button variant="primary" disabled={loading} onClick={onCreate}>Create</Button>
              <Button variant="ghost" disabled={loading} onClick={() => { setTitle("Interstellar"); setTimeElapsed(0); }}>Reset</Button>
            </div>
          </Card>

          <Card
            title="Update time_elapsed"
            subtitle="Demonstrates frequent writes + read-time enforcement."
            right={auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.update_time" /> : null}
          >
            <div className="field">
              <label>Film</label>
              <select value={editFilmId} onChange={(e) => setEditFilmId(e.target.value)}>
                <option value="" disabled>Select film</option>
                {items.map((f) => <option key={f.id} value={f.id}>{f.title} ({f.id.slice(0, 8)}…)</option>)}
              </select>
            </div>
            <div className="field">
              <label>New time_elapsed (seconds)</label>
              <input type="number" value={editTime} onChange={(e) => setEditTime(Number(e.target.value))} />
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <Button variant="primary" disabled={loading || !editFilmId} onClick={onUpdate}>Update</Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}


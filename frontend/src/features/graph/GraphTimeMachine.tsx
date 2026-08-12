import {useEffect, useMemo, useState} from "react";
import type {GraphOut} from "./graphModel";
import "./graph-time-machine.css";

export type GraphTimelineEvent = {id: number; payload: string; occurred_at: string};

export function graphTimeline(data: GraphOut, events: GraphTimelineEvent[] = []): number[] {
  if (events.length) return events.reduce<number[]>((frames, event) => {
    const parsed = Date.parse(event.occurred_at);
    if (Number.isFinite(parsed)) frames.push(Math.max(parsed, (frames.at(-1) || 0) + 1));
    return frames;
  }, []);
  return [...new Set([...data.nodes, ...data.edges]
    .map((item) => Date.parse(item.created_at || ""))
    .filter(Number.isFinite))].sort((a, b) => a - b);
}

export function graphAt(data: GraphOut, timestamp: number | null,
  events: GraphTimelineEvent[] = []): GraphOut {
  if (timestamp == null) return data;
  if (events.length) {
    const event = events[Math.max(0, frameIndex(graphTimeline(data, events), timestamp))];
    if (event) try { return JSON.parse(event.payload) as GraphOut; } catch { /* created_at fallback */ }
  }
  const nodes = data.nodes.filter((node) => {
    const created = Date.parse(node.created_at || "");
    return !Number.isFinite(created) || created <= timestamp;
  });
  const visible = new Set(nodes.map((node) => node.id));
  return {...data, nodes, edges: data.edges.filter((edge) => {
    const created = Date.parse(edge.created_at || "");
    return visible.has(edge.source) && visible.has(edge.target)
      && (!Number.isFinite(created) || created <= timestamp);
  })};
}

const stamp = (value: number) => new Intl.DateTimeFormat("ko-KR", {
  month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
}).format(value);
const frameIndex = (frames: number[], timestamp: number) => {
  for (let index = frames.length - 1; index >= 0; index -= 1)
    if (frames[index] <= timestamp) return index;
  return -1;
};

export default function GraphTimeMachine({data, events = [], timestamp, onChange}: {
  data: GraphOut;
  events?: GraphTimelineEvent[];
  timestamp: number | null;
  onChange: (timestamp: number | null) => void;
}) {
  const frames = useMemo(() => graphTimeline(data, events), [data, events]);
  const [playing, setPlaying] = useState(false);
  const index = timestamp == null ? Math.max(0, frames.length - 1)
    : Math.max(0, frameIndex(frames, timestamp));
  useEffect(() => {
    if (!playing || !frames.length) return;
    const timer = window.setInterval(() => {
      const current = timestamp == null ? -1 : frameIndex(frames, timestamp);
      if (current >= frames.length - 1) {
        setPlaying(false);
        onChange(null);
      } else onChange(frames[current + 1]);
    }, 700);
    return () => clearInterval(timer);
  }, [playing, timestamp, frames, onChange]);

  if (frames.length < 2) return <div className="graphTimeMachine graphTimeMachine--empty">
    <b>TIME-MACHINE</b><span>첫 변화 기록을 기다리는 중</span>
  </div>;
  return <div className={`graphTimeMachine${timestamp == null ? " is-live" : " is-paused"}`}>
    <div className="graphTimeMachine__identity">
      <b>TIME-MACHINE · {timestamp == null ? "● LIVE" : "Ⅱ REPLAY"}</b>
      <span>{timestamp == null ? stamp(frames.at(-1)!) : stamp(frames[index])}</span>
    </div>
    <button type="button" aria-label="이전 시점" disabled={index <= 0}
      onClick={() => onChange(frames[index - 1])}>◀</button>
    <button type="button" aria-label={playing ? "재생 정지" : "공격 과정 재생"}
      onClick={() => {
        if (playing) setPlaying(false);
        else { if (timestamp == null || index >= frames.length - 1) onChange(frames[0]); setPlaying(true); }
      }}>{playing ? "Ⅱ" : "▶"}</button>
    <input type="range" aria-label="공격 타임라인" min={0} max={frames.length - 1} value={index}
      onChange={(event) => { setPlaying(false); onChange(frames[Number(event.target.value)]); }} />
    <button type="button" aria-label="다음 시점" disabled={timestamp == null}
      onClick={() => index >= frames.length - 1 ? onChange(null) : onChange(frames[index + 1])}>▶</button>
    <button type="button" className="graphTimeMachine__live" disabled={timestamp == null}
      onClick={() => { setPlaying(false); onChange(null); }}>RETURN LIVE</button>
    <small>{index + 1}/{frames.length} EVENTS</small>
  </div>;
}

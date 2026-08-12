// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import GraphTimeMachine, {graphAt, graphTimeline} from "./GraphTimeMachine";
import type {GraphOut} from "./graphModel";

const data: GraphOut = {root_node_id: "root", nodes: [
  {id: "root", type: "project-root", label: "Lab", status: "in-progress", objective: false,
    source_ref: "", hidden: false, created_at: "2026-08-10T10:00:00Z"},
  {id: "host", type: "host", label: "10.0.0.1", status: "untried", objective: false,
    source_ref: "", hidden: false, created_at: "2026-08-11T10:00:00Z"},
  {id: "svc", type: "service", label: "80/tcp http", status: "untried", objective: false,
    source_ref: "", hidden: false, created_at: "2026-08-12T10:00:00Z"},
], edges: [
  {id: "a", source: "root", target: "host", relation: "discovered", status: "untried",
    created_at: "2026-08-11T10:00:01Z"},
  {id: "b", source: "host", target: "svc", relation: "discovered", status: "untried",
    created_at: "2026-08-12T10:00:01Z"},
]};

afterEach(cleanup);

it("reconstructs only nodes and valid edges present at a selected point", () => {
  const frames = graphTimeline(data);
  const snapshot = graphAt(data, Date.parse("2026-08-11T10:00:01Z"));
  expect(frames).toHaveLength(5);
  expect(snapshot.nodes.map((node) => node.id)).toEqual(["root", "host"]);
  expect(snapshot.edges.map((edge) => edge.id)).toEqual(["a"]);
});

it("returns to live mode explicitly", () => {
  const change = vi.fn();
  render(<GraphTimeMachine data={data} timestamp={Date.parse("2026-08-11T10:00:00Z")}
    onChange={change} />);
  fireEvent.click(screen.getByText("RETURN LIVE"));
  expect(change).toHaveBeenCalledWith(null);
});

it("prefers an append-only snapshot over inferred creation timestamps", () => {
  const snapshot = {...data, nodes: data.nodes.slice(0, 1), edges: []};
  const events = [{id: 1, occurred_at: "2026-08-12T12:00:00Z",
    payload: JSON.stringify(snapshot)}];
  expect(graphAt(data, Date.parse(events[0].occurred_at), events).nodes).toHaveLength(1);
  expect(graphTimeline(data, events)).toEqual([Date.parse(events[0].occurred_at)]);
});

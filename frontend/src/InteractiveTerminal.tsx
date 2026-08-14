import {useEffect, useRef} from "react";
import {DetachableTerminal, useFloatingTerminalState} from "./FloatingTerminal";
import PtyTerminal, {type PtyTerminalProps} from "./PtyTerminal";

export default function InteractiveTerminal(props: PtyTerminalProps & {
  floating?: boolean; autoFloat?: boolean;
}) {
  const floatingId = `pty-${props.sessionId}`;
  const floatingState = useFloatingTerminalState();
  const isFloating = !!floatingState?.isTerminalFloating(floatingId);
  // autoFloat has no inline/docked view of its own -- it only ever floats.
  // Once the user docks or closes that floating window, isFloating drops
  // back to false, and without this ref the render below would fall through
  // to <DetachableTerminal>, mounting a *second* PtyTerminal that tries to
  // reconnect to a session the backend already killed when the first one's
  // socket closed -- surfacing as a confusing "session already ended" error
  // right after the user only meant to move the window, not end it.
  const wasFloating = useRef(false);
  const lastSessionId = useRef(props.sessionId);
  if (lastSessionId.current !== props.sessionId) {
    lastSessionId.current = props.sessionId;
    wasFloating.current = false;
  }
  const terminal = <PtyTerminal {...props} onClose={() => {
    if (props.floating) floatingState?.closeTerminal(floatingId);
    props.onClose();
  }} />;
  useEffect(() => {
    if (isFloating) { wasFloating.current = true; return; }
    if (!props.autoFloat || !floatingState) return;
    if (wasFloating.current) { props.onClose(); return; }
    floatingState.floatTerminal({ id: floatingId,
      label: `${props.title || "대화형 터미널"} #${props.sessionId}`,
      content: <InteractiveTerminal {...props} floating autoFloat={false} /> },
    new DOMRect(Math.max(8, innerWidth - 760), 72, 720, 460));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.autoFloat, props.sessionId, isFloating]);
  if (props.floating) return terminal;
  if (props.autoFloat && (isFloating || wasFloating.current)) return null;
  return <DetachableTerminal id={floatingId}
    label={`${props.title || "대화형 터미널"} #${props.sessionId}`}
    floatingContent={<InteractiveTerminal {...props} floating />}>
    {terminal}
  </DetachableTerminal>;
}

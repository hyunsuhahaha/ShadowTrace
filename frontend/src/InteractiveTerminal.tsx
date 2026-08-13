import {useEffect} from "react";
import {DetachableTerminal, useFloatingTerminalState} from "./FloatingTerminal";
import PtyTerminal, {type PtyTerminalProps} from "./PtyTerminal";

export default function InteractiveTerminal(props: PtyTerminalProps & {
  floating?: boolean; autoFloat?: boolean;
}) {
  const floatingId = `pty-${props.sessionId}`;
  const floatingState = useFloatingTerminalState();
  const terminal = <PtyTerminal {...props} onClose={() => {
    if (props.floating) floatingState?.closeTerminal(floatingId);
    props.onClose();
  }} />;
  useEffect(() => {
    if (!props.autoFloat || !floatingState || floatingState.isTerminalFloating(floatingId)) return;
    floatingState.floatTerminal({ id: floatingId,
      label: `${props.title || "대화형 터미널"} #${props.sessionId}`,
      content: <InteractiveTerminal {...props} floating autoFloat={false} /> },
    new DOMRect(Math.max(8, innerWidth - 760), 72, 720, 460));
  }, [props.autoFloat, props.sessionId]);
  if (props.floating) return terminal;
  if (props.autoFloat && floatingState?.isTerminalFloating(floatingId)) return null;
  return <DetachableTerminal id={floatingId}
    label={`${props.title || "대화형 터미널"} #${props.sessionId}`}
    floatingContent={<InteractiveTerminal {...props} floating />}>
    {terminal}
  </DetachableTerminal>;
}

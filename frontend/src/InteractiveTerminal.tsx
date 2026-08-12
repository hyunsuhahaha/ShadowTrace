import {DetachableTerminal, useFloatingTerminalState} from "./FloatingTerminal";
import PtyTerminal, {type PtyTerminalProps} from "./PtyTerminal";

export default function InteractiveTerminal(props: PtyTerminalProps & {floating?: boolean}) {
  const floatingId = `pty-${props.sessionId}`;
  const floatingState = useFloatingTerminalState();
  const terminal = <PtyTerminal {...props} onClose={() => {
    if (props.floating) floatingState?.closeTerminal(floatingId);
    props.onClose();
  }} />;
  if (props.floating) return terminal;
  return <DetachableTerminal id={floatingId}
    label={`${props.title || "대화형 터미널"} #${props.sessionId}`}
    floatingContent={<InteractiveTerminal {...props} floating />}>
    {terminal}
  </DetachableTerminal>;
}

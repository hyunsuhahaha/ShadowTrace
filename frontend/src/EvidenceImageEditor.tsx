import { useEffect, useRef, useState } from "react";
import { Button } from "./ui";

type Tool = "box" | "arrow" | "text" | "mosaic" | "crop";
type Point = { x: number; y: number };
type Operation = { tool: Tool; start: Point; end: Point; text?: string };
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch("/api" + path, init);
  if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
  return response.json();
};

export default function EvidenceImageEditor({ evidence, onClose }: {
  evidence: { id: number; title: string }; onClose: () => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const imageRef = useRef<HTMLImageElement>();
  const [tool, setTool] = useState<Tool>("box");
  const [operations, setOperations] = useState<Operation[]>([]);
  const [redo, setRedo] = useState<Operation[]>([]);
  const [start, setStart] = useState<Point>();
  const [text, setText] = useState("Finding");
  const [caption, setCaption] = useState(evidence.title);
  const [message, setMessage] = useState("이미지를 불러오는 중…");

  const drawArrow = (context: CanvasRenderingContext2D, from: Point, to: Point) => {
    const angle = Math.atan2(to.y - from.y, to.x - from.x);
    context.beginPath(); context.moveTo(from.x, from.y); context.lineTo(to.x, to.y);
    context.moveTo(to.x, to.y); context.lineTo(to.x - 14 * Math.cos(angle - Math.PI / 6), to.y - 14 * Math.sin(angle - Math.PI / 6));
    context.moveTo(to.x, to.y); context.lineTo(to.x - 14 * Math.cos(angle + Math.PI / 6), to.y - 14 * Math.sin(angle + Math.PI / 6)); context.stroke();
  };
  const paint = (rows = operations) => {
    const canvas = canvasRef.current, image = imageRef.current;
    if (!canvas || !image) return;
    const context = canvas.getContext("2d")!;
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    context.lineWidth = 3; context.strokeStyle = "#e84f4f"; context.fillStyle = "#e84f4f";
    context.font = "600 18px sans-serif";
    for (const row of rows) {
      const x = Math.min(row.start.x, row.end.x), y = Math.min(row.start.y, row.end.y);
      const width = Math.abs(row.end.x - row.start.x), height = Math.abs(row.end.y - row.start.y);
      if (row.tool === "box" || row.tool === "crop") {
        context.save(); if (row.tool === "crop") context.setLineDash([8, 5]);
        context.strokeStyle = row.tool === "crop" ? "#a8d5ba" : "#e84f4f";
        context.strokeRect(x, y, width, height); context.restore();
      } else if (row.tool === "arrow") drawArrow(context, row.start, row.end);
      else if (row.tool === "text") {
        context.fillStyle = "rgba(0,0,0,.72)"; const measured = context.measureText(row.text || "").width;
        context.fillRect(row.start.x - 5, row.start.y - 21, measured + 10, 27);
        context.fillStyle = "#fff"; context.fillText(row.text || "", row.start.x, row.start.y);
      } else if (row.tool === "mosaic" && width > 2 && height > 2) {
        const size = 12;
        for (let py = y; py < y + height; py += size) for (let px = x; px < x + width; px += size) {
          const pixel = context.getImageData(Math.min(px + size / 2, canvas.width - 1), Math.min(py + size / 2, canvas.height - 1), 1, 1).data;
          context.fillStyle = `rgb(${pixel[0]},${pixel[1]},${pixel[2]})`;
          context.fillRect(px, py, Math.min(size, x + width - px), Math.min(size, y + height - py));
        }
      }
    }
  };
  useEffect(() => {
    const image = new Image();
    image.onload = () => {
      imageRef.current = image;
      const canvas = canvasRef.current!;
      const scale = Math.min(1, 1100 / image.naturalWidth, 700 / image.naturalHeight);
      canvas.width = Math.round(image.naturalWidth * scale);
      canvas.height = Math.round(image.naturalHeight * scale);
      paint([]); setMessage("원본은 변경되지 않습니다.");
    };
    image.onerror = () => setMessage("이미지를 불러오지 못했습니다.");
    image.src = `/api/evidence/${evidence.id}/file`;
  }, [evidence.id]);
  useEffect(() => { paint(); }, [operations]);

  const point = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    return { x: (event.clientX - rect.left) * event.currentTarget.width / rect.width,
      y: (event.clientY - rect.top) * event.currentTarget.height / rect.height };
  };
  const complete = (end: Point) => {
    if (!start) return;
    const operation = { tool, start, end, text: tool === "text" ? text : undefined };
    setOperations((rows) => [...rows, operation]); setRedo([]); setStart(undefined);
  };
  const save = async () => {
    const source = canvasRef.current!;
    const crop = [...operations].reverse().find((row) => row.tool === "crop");
    paint(operations.filter((row) => row.tool !== "crop"));
    let output = source;
    if (crop) {
      const x = Math.max(0, Math.min(crop.start.x, crop.end.x));
      const y = Math.max(0, Math.min(crop.start.y, crop.end.y));
      const width = Math.min(source.width - x, Math.abs(crop.end.x - crop.start.x));
      const height = Math.min(source.height - y, Math.abs(crop.end.y - crop.start.y));
      if (width > 5 && height > 5) {
        output = document.createElement("canvas"); output.width = width; output.height = height;
        output.getContext("2d")!.drawImage(source, x, y, width, height, 0, 0, width, height);
      }
    }
    setMessage("파생 이미지를 저장하는 중…");
    try {
      const encoded = output.toDataURL("image/png").split(",", 2)[1];
      paint();
      const result = await api<{ version: number }>(`/evidence/${evidence.id}/image-edits`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operations, caption, rendered_png_base64: encoded }),
      });
      setMessage(`편집 버전 ${result.version}을 저장했습니다.`); setTimeout(onClose, 700);
    } catch (error) { setMessage(String(error)); }
  };
  return <div className="imageEditorModal" role="dialog" aria-modal="true" aria-label={`${evidence.title} 이미지 편집`}>
    <section>
      <header><div><span>NON-DESTRUCTIVE EDIT</span><h2>{evidence.title}</h2><p>{message}</p></div><button aria-label="닫기" onClick={onClose}>×</button></header>
      <div className="imageEditorTools">
        {(["crop", "box", "arrow", "text", "mosaic"] as Tool[]).map((value) => <button className={tool === value ? "active" : ""} key={value} onClick={() => setTool(value)}>{({ crop: "크롭", box: "박스", arrow: "화살표", text: "텍스트", mosaic: "모자이크" })[value]}</button>)}
        <input aria-label="주석 텍스트" value={text} onChange={(event) => setText(event.target.value)} disabled={tool !== "text"} />
        <button disabled={!operations.length} onClick={() => { const last = operations.at(-1)!; setOperations(operations.slice(0, -1)); setRedo([last, ...redo]); }}>실행 취소</button>
        <button disabled={!redo.length} onClick={() => { setOperations([...operations, redo[0]]); setRedo(redo.slice(1)); }}>다시 실행</button>
        <button disabled={!operations.length} onClick={() => { setOperations([]); setRedo([]); }}>모두 삭제</button>
      </div>
      <div className="imageCanvas"><canvas ref={canvasRef} onPointerDown={(event) => setStart(point(event))} onPointerUp={(event) => complete(point(event))} /></div>
      <footer><label>보고서 캡션<input value={caption} onChange={(event) => setCaption(event.target.value)} /></label><Button onClick={onClose}>취소</Button><Button variant="primary" onClick={save}>새 편집 버전 저장</Button></footer>
    </section>
  </div>;
}

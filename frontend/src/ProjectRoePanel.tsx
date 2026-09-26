import {useEffect, useState} from "react";
import {useQuery, useQueryClient} from "@tanstack/react-query";
import {Button} from "./ui";

type Roe={project_id:number;status:string;included_targets:string[];excluded_targets:string[];
  asset_ids:number[];allowed_actions:string[];valid_from:string|null;valid_until:string|null;
  notes:string;approved_by:string;approval_reason:string;revision:number};
type Asset={id:number;name:string;kind:string;scope_status:string};
const actions=["scan","command","web","session","post","runbook"];
const labels:Record<string,string>={scan:"스캔",command:"명령 실행",web:"HTTP 요청",session:"세션",post:"접근 후 실행",runbook:"Runbook 검사"};
async function call<T>(path:string,init?:RequestInit):Promise<T>{
  const r=await fetch(`/api${path}`,{cache:"no-store",...init});
  if(!r.ok){const body=await r.json().catch(()=>({}));throw new Error(typeof body.detail==="string"?body.detail:JSON.stringify(body.detail||r.statusText));}
  return r.json();
}
const json=(value:unknown,method="POST"):RequestInit=>({method,headers:{"Content-Type":"application/json"},body:JSON.stringify(value)});
const localDate=(value:string|null)=>value?new Date(value).toISOString().slice(0,16):"";

export default function ProjectRoePanel({projectId,assets}:{projectId:number;assets:Asset[]}){
  const qc=useQueryClient();
  const roe=useQuery({queryKey:["projectRoe",projectId],queryFn:()=>call<Roe>(`/projects/${projectId}/roe`)});
  const history=useQuery({queryKey:["projectRoeHistory",projectId],queryFn:()=>call<{id:number;action:string;actor:string;revision:number;occurred_at:string}[]>(`/projects/${projectId}/roe/history`)});
  const[targets,setTargets]=useState(""),[excluded,setExcluded]=useState("");
  const[assetIds,setAssetIds]=useState<number[]>([]),[selectedActions,setSelectedActions]=useState<string[]>([]);
  const[from,setFrom]=useState(""),[until,setUntil]=useState(""),[notes,setNotes]=useState("");
  const[actor,setActor]=useState(""),[reason,setReason]=useState("");
  const[busy,setBusy]=useState(false),[error,setError]=useState("");
  useEffect(()=>{if(!roe.data)return;setTargets(roe.data.included_targets.join("\n"));
    setExcluded(roe.data.excluded_targets.join("\n"));setAssetIds(roe.data.asset_ids);
    setSelectedActions(roe.data.allowed_actions);setFrom(localDate(roe.data.valid_from));
    setUntil(localDate(roe.data.valid_until));setNotes(roe.data.notes);},[roe.data]);
  async function perform(work:()=>Promise<unknown>){setBusy(true);setError("");try{await work();
    await Promise.all([qc.invalidateQueries({queryKey:["projectRoe",projectId]}),
      qc.invalidateQueries({queryKey:["projectRoeHistory",projectId]})]);
  }catch(exc){setError(String(exc));}finally{setBusy(false);}}
  const lines=(value:string)=>[...new Set(value.split(/[\n,]/).map(item=>item.trim()).filter(Boolean))];
  return <details className="assessmentRoe" open={roe.data?.status!=="approved"}>
    <summary><span>프로젝트 승인 범위</span><strong>{roe.data?.status||"불러오는 중"}</strong><small>revision {roe.data?.revision||1}</small></summary>
    <div className="assessmentRoeBody"><p>승인 대상·제외 대상·기간·허용 행위를 저장합니다. 변경 시 이전 승인은 무효가 됩니다.</p>
      <div className="assessmentRoeGrid"><label>허용 IP·CIDR·호스트명 (줄마다 하나)<textarea rows={3} value={targets} onChange={event=>setTargets(event.target.value)}/></label>
        <label>제외 대상<textarea rows={3} value={excluded} onChange={event=>setExcluded(event.target.value)}/></label>
        <label>시작<input type="datetime-local" value={from} onChange={event=>setFrom(event.target.value)}/></label>
        <label>종료<input type="datetime-local" value={until} onChange={event=>setUntil(event.target.value)}/></label></div>
      <fieldset><legend>허용 작업</legend><div className="assessmentRoeChoices">{actions.map(action=><label key={action}><input type="checkbox" checked={selectedActions.includes(action)} onChange={event=>setSelectedActions(current=>event.target.checked?[...current,action]:current.filter(value=>value!==action))}/>{labels[action]}</label>)}</div></fieldset>
      <fieldset><legend>허용 자산</legend><div className="assessmentRoeChoices">{assets.map(asset=><label key={asset.id}><input type="checkbox" checked={assetIds.includes(asset.id)} onChange={event=>setAssetIds(current=>event.target.checked?[...current,asset.id]:current.filter(value=>value!==asset.id))}/>{asset.kind} · {asset.name}</label>)}</div></fieldset>
      <label>운영 메모<textarea rows={2} value={notes} onChange={event=>setNotes(event.target.value)}/></label>
      <div className="assessmentRoeActions"><Button disabled={busy||!from||!until} onClick={()=>perform(()=>call(`/projects/${projectId}/roe`,json({included_targets:lines(targets),excluded_targets:lines(excluded),asset_ids:assetIds,allowed_actions:selectedActions,valid_from:new Date(from).toISOString(),valid_until:new Date(until).toISOString(),notes},"PUT")))}>범위 초안 저장</Button>
        <label>승인자<input value={actor} onChange={event=>setActor(event.target.value)}/></label>
        <label>승인·취소 사유<input value={reason} onChange={event=>setReason(event.target.value)}/></label>
        <Button variant="primary" disabled={busy||!actor.trim()||!reason.trim()||roe.data?.status==="approved"} onClick={()=>perform(()=>call(`/projects/${projectId}/roe/approve`,json({actor,reason})))}>승인</Button>
        <Button disabled={busy||!actor.trim()||!reason.trim()||roe.data?.status!=="approved"} onClick={()=>perform(()=>call(`/projects/${projectId}/roe/revoke`,json({actor,reason})))}>승인 취소</Button></div>
      {error&&<p className="assessmentError" role="alert">{error}</p>}
      {!!history.data?.length&&<div className="assessmentRoeHistory"><strong>승인 이력</strong>{history.data.map(item=><span key={item.id}>{item.action} · rev {item.revision} · {item.actor} · {new Date(item.occurred_at).toLocaleString()}</span>)}</div>}
    </div>
  </details>;
}

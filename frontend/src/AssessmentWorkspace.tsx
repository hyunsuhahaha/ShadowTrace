import {useEffect, useMemo, useState} from "react";
import {useQuery, useQueryClient} from "@tanstack/react-query";
import {Button, EmptyState, ErrorState, LoadingState, PageHeader} from "./ui";
import ProjectRoePanel from "./ProjectRoePanel";
import "./assessment-workspace.css";

type Kind = "web" | "api" | "mobile" | "cloud" | "kubernetes" | "source" | "wireless" | "ics";
type Asset = {id:number;project_id:number;kind:Kind;name:string;locator:string;
  details:string;scope_status:"pending"|"in_scope"|"out_of_scope"};
type Subject = {id:number;asset_id:number;kind:string;label:string;identifier:string;
  attributes:string;scope_status:"pending"|"in_scope"|"out_of_scope"};
type Template = {id:number;name:string;tags:string[];latest_version_id:number|null};
type Step = {id:number;position:number;title:string;description:string;status:string;
  outcome:string;activation:string;result:string;notes:string;status_reason:string;
  approval_status:string;approval_reason:string;evidence_ids:number[];
  observations:{id:number;title:string;status:string}[]};
type Instance = {id:number;asset_id:number|null;template_name:string;progress:{completed:number;total:number};steps?:Step[]};
type Evidence = {id:number;title:string;original_name:string;sensitivity:string;asset_id:number|null};
const KINDS: {id:Kind;label:string;hint:string}[] = [
  {id:"web",label:"Web",hint:"기능·URL·역할"},
  {id:"api",label:"API",hint:"명세·버전·객체"},
  {id:"mobile",label:"Mobile",hint:"패키지·빌드·플랫폼"},
  {id:"cloud",label:"Cloud",hint:"계정·테넌트·리소스"},
  {id:"kubernetes",label:"Kubernetes",hint:"클러스터·namespace·workload"},
  {id:"source",label:"Source",hint:"저장소·커밋"},
  {id:"wireless",label:"Wireless",hint:"SSID·BSSID·장소"},
  {id:"ics",label:"OT / ICS",hint:"설비·공정·세그먼트"},
];
const SUBJECT_FIELDS: Record<Kind,Record<string,string[]>> = {
  web:{web_function:["url","role"],web_role:["base_url"],web_object:["role","object_type"]},
  api:{api_operation:["method","path","version","caller"],api_schema:["version","schema_ref"],
    api_object:["caller","object_type"]},
  mobile:{mobile_build:["package_id","platform","build_id"],mobile_device:["platform","device_model"]},
  cloud:{cloud_account:["provider","account_id"],cloud_role:["provider","account_id","role_id"],
    cloud_resource:["provider","account_id","resource_id"]},
  kubernetes:{k8s_namespace:["cluster","namespace"],k8s_workload:["cluster","namespace","workload"],
    k8s_service_account:["cluster","namespace","service_account"]},
  source:{source_commit:["repository","commit_sha"],source_package:["repository","package","version"]},
  wireless:{wireless_ap:["ssid","bssid","site"],wireless_site:["site","location"]},
  ics:{ics_device:["device","process","segment","operator_approval"],
    ics_process:["process","segment","operator_approval"],
    ics_approval:["operator","window","safety_limit"]},
};
const OUTCOMES = ["unknown","confirmed","not_found","access_denied","authentication_required","blocked","error"];
const STATUSES = ["not_started","in_progress","completed","attempted","blocked","skipped","suspicious","not_applicable"];
async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(`/api${path}`,{cache:"no-store",...init});
  if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(
    typeof body.detail==="string"?body.detail:JSON.stringify(body.detail||response.statusText));}
  return response.status===204?undefined as T:response.json();
}
const json=(value:unknown,method="POST"):RequestInit=>({method,headers:{"Content-Type":"application/json"},body:JSON.stringify(value)});

function StepEditor({step,asset,projectId,onChanged}:{step:Step;asset:Asset;projectId:number;onChanged:()=>Promise<void>}){
  const[status,setStatus]=useState(step.status),[outcome,setOutcome]=useState(step.outcome);
  const[result,setResult]=useState(step.result),[notes,setNotes]=useState(step.notes);
  const[reason,setReason]=useState(step.status_reason),[approvalReason,setApprovalReason]=useState(step.approval_reason||"");
  const[observationTitle,setObservationTitle]=useState("");
  const[busy,setBusy]=useState(false),[error,setError]=useState("");
  const evidence=useQuery({queryKey:["assessmentEvidence",asset.id],
    queryFn:()=>request<Evidence[]>(`/evidence?asset_id=${asset.id}`)});
  useEffect(()=>{setStatus(step.status);setOutcome(step.outcome);setResult(step.result);
    setNotes(step.notes);setReason(step.status_reason);},[step.id,step.status,step.outcome,step.result,step.notes,step.status_reason]);
  async function act(work:()=>Promise<unknown>){
    setBusy(true);setError("");
    try{await work();await onChanged();}catch(exc){setError(String(exc));}finally{setBusy(false);}
  }
  const locked=["waiting","excluded","awaiting_approval"].includes(step.activation);
  return <article className="assessmentStep" id={`assessment-step-${step.id}`}>
    <header><span className="assessmentStepIndex">{String(step.position).padStart(2,"0")}</span>
      <div><strong>{step.title}</strong><small>{step.activation} · {step.status}</small></div></header>
    {step.description&&<p>{step.description}</p>}
    {step.approval_status==="pending"&&<div className="assessmentApproval">
      <label>승인 근거<input value={approvalReason} onChange={event=>setApprovalReason(event.target.value)} placeholder="승인자와 허용 범위" /></label>
      <Button disabled={busy||!approvalReason.trim()||asset.scope_status!=="in_scope"}
        onClick={()=>act(()=>request(`/runbooks/steps/${step.id}/approval`,json({decision:"approved",reason:approvalReason,actor:"local"})))}>단계 승인</Button>
      <Button disabled={busy||!approvalReason.trim()} onClick={()=>act(()=>request(`/runbooks/steps/${step.id}/approval`,json({decision:"rejected",reason:approvalReason,actor:"local"})))}>거부</Button>
    </div>}
    <div className="assessmentStepControls">
      <label>상태<select value={status} onChange={event=>setStatus(event.target.value)}>{STATUSES.map(value=><option key={value}>{value}</option>)}</select></label>
      <label>판정<select value={outcome} onChange={event=>setOutcome(event.target.value)}>{OUTCOMES.map(value=><option key={value}>{value}</option>)}</select></label>
      <label>사유<input value={reason} onChange={event=>setReason(event.target.value)} placeholder="보류·제외·차단 사유" /></label>
    </div>
    <label>검사 결과<textarea value={result} onChange={event=>setResult(event.target.value)} rows={2} /></label>
    <label>작업 메모<textarea value={notes} onChange={event=>setNotes(event.target.value)} rows={2} /></label>
    <div className="assessmentStepActions">
      <Button variant="primary" disabled={busy||asset.scope_status!=="in_scope"||locked}
        onClick={()=>act(()=>request(`/runbooks/steps/${step.id}`,json({status,outcome,result,notes,status_reason:reason},"PATCH")))}>판정 저장</Button>
      <select aria-label="연결할 증거" defaultValue="" onChange={event=>{const id=Number(event.target.value);if(id)act(()=>request(`/runbooks/steps/${step.id}/evidence`,json({resource_id:id})));event.target.value="";}}>
        <option value="">증거 연결…</option>{evidence.data?.map(item=><option key={item.id} value={item.id}>{item.title}</option>)}
      </select>
      <span>증거 {step.evidence_ids.length} · 관찰 {step.observations.length}</span>
    </div>
    {step.evidence_ids.length>0&&<div className="assessmentLinked">{step.evidence_ids.map(id=>{
      const item=evidence.data?.find(row=>row.id===id);
      return <a key={id} href={`/api/evidence/${id}/file`}>{item?.sensitivity==="normal"?item.title:`Evidence #${id}`} ↗</a>;
    })}</div>}
    <div className="assessmentObservation"><input value={observationTitle} onChange={event=>setObservationTitle(event.target.value)} placeholder="관찰 결과 제목" />
      <Button disabled={busy||!observationTitle.trim()} onClick={()=>act(async()=>{await request(`/runbooks/steps/${step.id}/observations`,json({title:observationTitle,detail:result}));setObservationTitle("");})}>관찰 기록</Button></div>
    {step.observations.map(item=><div className="assessmentObservationRow" key={item.id}><span>{item.title} · {item.status}</span>
      {item.status!=="promoted"&&<Button disabled={busy} onClick={()=>act(()=>request(`/runbooks/observations/${item.id}/promote`,json({title:item.title,description:result}))) }>Finding 승격</Button>}</div>)}
    {error&&<p role="alert" className="assessmentError">{error}</p>}
  </article>;
}

export default function AssessmentWorkspace({initialAssetId,initialStepId}:{initialAssetId?:number;initialStepId?:number}={}){
  const qc=useQueryClient();
  const[projectId,setProjectId]=useState(()=>Number(localStorage.getItem("oscp-workspace-project")));
  const[selectedId,setSelectedId]=useState<number|undefined>(initialAssetId);
  const[selectedInstanceId,setSelectedInstanceId]=useState<number>();
  const[kind,setKind]=useState<Kind>("mobile"),[name,setName]=useState(""),[locator,setLocator]=useState("");
  const[details,setDetails]=useState("{}");
  const[subjectKind,setSubjectKind]=useState(""),[subjectLabel,setSubjectLabel]=useState("");
  const[subjectIdentifier,setSubjectIdentifier]=useState("");
  const[subjectAttributes,setSubjectAttributes]=useState<Record<string,string>>({});
  const[busy,setBusy]=useState(false),[error,setError]=useState("");
  useEffect(()=>{const onProject=(event:Event)=>{setProjectId((event as CustomEvent<number>).detail);setSelectedId(undefined);};
    addEventListener("oscp-project-change",onProject);return()=>removeEventListener("oscp-project-change",onProject);},[]);
  useEffect(()=>{if(initialAssetId)setSelectedId(initialAssetId);},[initialAssetId]);
  const assets=useQuery({queryKey:["assessmentAssets",projectId],
    queryFn:()=>request<Asset[]>(`/assessment-assets?project_id=${projectId}`),enabled:!!projectId});
  const templates=useQuery({queryKey:["runbookTemplates"],queryFn:()=>request<Template[]>("/runbooks/templates")});
  const instances=useQuery({queryKey:["assessmentInstances",projectId],
    queryFn:()=>request<Instance[]>(`/runbooks/instances?project_id=${projectId}`),enabled:!!projectId});
  const selected=assets.data?.find(item=>item.id===selectedId)||assets.data?.[0];
  const subjectKinds=selected?Object.keys(SUBJECT_FIELDS[selected.kind]):[];
  useEffect(()=>{setSubjectKind(subjectKinds[0]||"");setSubjectAttributes({});
    setSubjectLabel("");setSubjectIdentifier("");},[selected?.id]);
  const subjects=useQuery({queryKey:["assessmentSubjects",selected?.id],
    queryFn:()=>request<Subject[]>(`/assessment-asset-subjects?asset_id=${selected?.id}`),enabled:!!selected});
  useEffect(()=>{if(selected&&selected.id!==selectedId)setSelectedId(selected.id);},[selected?.id,selectedId]);
  const selectedInstances=instances.data?.filter(item=>item.asset_id===selected?.id)||[];
  const activeInstance=selectedInstances.find(item=>item.id===selectedInstanceId)||selectedInstances[0];
  const detail=useQuery({queryKey:["assessmentInstance",activeInstance?.id],
    queryFn:()=>request<Instance>(`/runbooks/instances/${activeInstance.id}`),enabled:!!activeInstance});
  useEffect(()=>{if(!initialStepId||!detail.data?.steps?.some(step=>step.id===initialStepId))return;
    const timer=setTimeout(()=>document.getElementById(`assessment-step-${initialStepId}`)?.scrollIntoView({block:"center"}),120);
    return()=>clearTimeout(timer);},[initialStepId,detail.data]);
  const evidence=useQuery({queryKey:["assessmentEvidence",selected?.id],
    queryFn:()=>request<Evidence[]>(`/evidence?asset_id=${selected?.id}`),enabled:!!selected});
  const matching=useMemo(()=>templates.data?.filter(item=>selected&&(
    item.tags.includes(selected.kind)||selected.kind==="web"&&item.name.includes("웹")))||[],[templates.data,selected?.kind]);
  async function mutate(work:()=>Promise<unknown>){setBusy(true);setError("");try{await work();
    await Promise.all([qc.invalidateQueries({queryKey:["assessmentAssets"]}),qc.invalidateQueries({queryKey:["assessmentInstances"]}),
      qc.invalidateQueries({queryKey:["assessmentInstance"]}),qc.invalidateQueries({queryKey:["assessmentEvidence"]}),
      qc.invalidateQueries({queryKey:["assessmentSubjects"]})]);
    if(projectId)await request(`/projects/${projectId}/graph/sync`,{method:"POST"});
  }catch(exc){setError(String(exc));}finally{setBusy(false);}}
  if(!projectId)return <EmptyState title="프로젝트를 선택하세요" description="평가 자산은 프로젝트별로 관리됩니다."/>;
  if(assets.isLoading)return <LoadingState label="평가 자산 불러오는 중"/>;
  if(assets.error)return <ErrorState message="평가 자산을 불러오지 못했습니다."/>;
  return <main className="assessmentWorkspace">
    <PageHeader eyebrow="ASSESSMENT SCOPE" title="평가 자산" description="IP 호스트 밖의 대상과 실제 검사 결과를 한곳에서 연결합니다."
      actions={<a className="assessmentGraphLink" href="#graph">Graph에서 보기 ↗</a>}/>
    <ProjectRoePanel projectId={projectId} assets={assets.data||[]}/>
    <div className="assessmentLayout">
      <aside className="assessmentRail">
        <form onSubmit={event=>{event.preventDefault();mutate(async()=>{const row=await request<Asset>("/assessment-assets",json({project_id:projectId,kind,name,locator,details:JSON.parse(details),scope_status:"pending"}));setSelectedId(row.id);setName("");setLocator("");setDetails("{}");});}}>
          <h2>자산 등록</h2><label>유형<select value={kind} onChange={event=>setKind(event.target.value as Kind)}>{KINDS.map(item=><option value={item.id} key={item.id}>{item.label}</option>)}</select></label>
          <label>이름<input required maxLength={200} value={name} onChange={event=>setName(event.target.value)} placeholder={KINDS.find(item=>item.id===kind)?.hint}/></label>
          <label>식별자<input maxLength={500} value={locator} onChange={event=>setLocator(event.target.value)} placeholder="URL · ARN · package ID · commit SHA"/></label>
          <label>상세 JSON<textarea value={details} onChange={event=>setDetails(event.target.value)} rows={2}/></label>
          <Button variant="primary" disabled={busy||!name.trim()}>등록</Button>
        </form>
        <div className="assessmentAssetList" role="list">{assets.data?.map(item=><button role="listitem" type="button" key={item.id}
          className={selected?.id===item.id?"selected":""} onClick={()=>setSelectedId(item.id)}>
          <span>{KINDS.find(kind=>kind.id===item.kind)?.label}</span><strong>{item.name}</strong><small>{item.scope_status}</small>
        </button>)}</div>
      </aside>
      <section className="assessmentMain">{!selected?<EmptyState title="등록된 자산이 없습니다" description="모바일 앱, 클라우드 계정, 저장소 등 실제 평가 단위를 등록하세요."/>:<>
        <header className="assessmentAssetHeader"><div><small>{selected.kind.toUpperCase()} · ASSET #{selected.id}</small><h2>{selected.name}</h2><p>{selected.locator||"식별자 없음"}</p></div>
          <label>범위 상태<select value={selected.scope_status} disabled={busy} onChange={event=>mutate(()=>request(`/assessment-assets/${selected.id}`,json({project_id:projectId,kind:selected.kind,name:selected.name,locator:selected.locator,details:JSON.parse(selected.details||"{}"),scope_status:event.target.value},"PUT")))}>
            <option value="pending">승인 대기</option><option value="in_scope">범위 안</option><option value="out_of_scope">범위 밖</option>
          </select></label></header>
        <section className="assessmentSubjects" aria-label="유형별 세부 평가 대상">
          <h3>세부 평가 대상</h3>
          <p>빌드·역할·리소스·workload·커밋·무선 AP·제어 장비를 각각 범위 노드로 기록합니다.</p>
          <form onSubmit={event=>{event.preventDefault();const fields=SUBJECT_FIELDS[selected.kind][subjectKind]||[];
            const attributes=Object.fromEntries(fields.map(field=>[field,subjectAttributes[field]||""]));
            mutate(async()=>{await request("/assessment-asset-subjects",json({asset_id:selected.id,
              kind:subjectKind,label:subjectLabel,identifier:subjectIdentifier,attributes,
              scope_status:"pending"}));setSubjectLabel("");setSubjectIdentifier("");setSubjectAttributes({});});}}>
            <label>세부 유형<select value={subjectKind} onChange={event=>{setSubjectKind(event.target.value);setSubjectAttributes({});}}>
              {subjectKinds.map(item=><option key={item} value={item}>{item.replaceAll("_"," ")}</option>)}</select></label>
            <label>이름<input required value={subjectLabel} maxLength={200} onChange={event=>setSubjectLabel(event.target.value)}/></label>
            <label>식별자<input required value={subjectIdentifier} maxLength={500} onChange={event=>setSubjectIdentifier(event.target.value)}/></label>
            {(SUBJECT_FIELDS[selected.kind][subjectKind]||[]).map(field=><label key={field}>{field.replaceAll("_"," ")}
              <input required value={subjectAttributes[field]||""} maxLength={500}
                onChange={event=>setSubjectAttributes(current=>({...current,[field]:event.target.value}))}/></label>)}
            <Button disabled={busy||!subjectLabel.trim()||!subjectIdentifier.trim()}>세부 대상 추가</Button>
          </form>
          <div className="assessmentSubjectList">{subjects.data?.map(item=><article key={item.id}>
            <strong>{item.label}</strong><small>{item.kind.replaceAll("_"," ")} · {item.identifier}</small>
            <label>범위<select value={item.scope_status} disabled={busy} onChange={event=>mutate(()=>
              request(`/assessment-asset-subjects/${item.id}`,json({asset_id:selected.id,kind:item.kind,
                label:item.label,identifier:item.identifier,attributes:JSON.parse(item.attributes),
                scope_status:event.target.value},"PUT")))}>
              <option value="pending">대기</option><option value="in_scope">범위 안</option>
              <option value="out_of_scope">범위 밖</option></select></label>
            <Button disabled={busy} onClick={()=>mutate(()=>request(`/assessment-asset-subjects/${item.id}`,{method:"DELETE"}))}>삭제</Button>
          </article>)}</div>
        </section>
        <div className="assessmentToolbar"><label>절차 적용<select defaultValue="" disabled={busy||selected.scope_status==="out_of_scope"} onChange={event=>{const id=Number(event.target.value);if(id)mutate(()=>request("/runbooks/instances",json({version_id:id,asset_id:selected.id})));event.target.value="";}}>
          <option value="">Runbook 선택…</option>{matching.map(item=><option key={item.id} value={item.latest_version_id||""}>{item.name}</option>)}
        </select></label><label className="assessmentUpload">증거 업로드<input type="file" onChange={event=>{const file=event.target.files?.[0];if(!file)return;
          mutate(async()=>{const data=new FormData();data.append("project_id",String(projectId));data.append("asset_id",String(selected.id));data.append("title",file.name);data.append("file",file);
            await request("/evidence/upload-asset",{method:"POST",body:data});});event.target.value="";}}/></label></div>
        {evidence.data?.length? <div className="assessmentEvidence"><strong>증거 {evidence.data.length}</strong>{evidence.data.map(item=><a key={item.id} href={`/api/evidence/${item.id}/file`}>{item.sensitivity==="normal"?item.title:`Evidence #${item.id}`} ↗</a>)}</div>:null}
        {selectedInstances.length>1&&<label>적용된 Runbook<select value={activeInstance?.id||""} onChange={event=>setSelectedInstanceId(Number(event.target.value))}>
          {selectedInstances.map(item=><option key={item.id} value={item.id}>{item.template_name}</option>)}</select></label>}
        {activeInstance&&<section className="assessmentRunbook"><h3>{activeInstance.template_name} <small>{activeInstance.progress.completed}/{activeInstance.progress.total}</small></h3>
          {detail.data?.steps?.map(step=><StepEditor key={step.id} step={step} asset={selected} projectId={projectId}
            onChanged={async()=>{await qc.invalidateQueries({queryKey:["assessmentInstance"]});await request(`/projects/${projectId}/graph/sync`,{method:"POST"});}}/>)}</section>}
      </>}</section>
    </div>{error&&<p role="alert" className="assessmentError">{error}</p>}
  </main>;
}

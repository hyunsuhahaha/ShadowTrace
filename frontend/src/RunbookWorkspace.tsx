import {useEffect, useRef, useState} from "react";
import {useMutation, useQuery, useQueryClient} from "@tanstack/react-query";
import {Badge, Button, Card, EmptyState, ErrorState, LoadingState, PageHeader} from "./ui";

type Project={id:number;name:string};
type Target={id:number;project_id:number;name:string;ip:string};
type Service={id:number;target_id:number;name:string;port:number;protocol:string};
type Template={id:number;name:string;description:string;service_names:string[];ports:number[];
  latest_version:number|null;latest_version_id:number|null;origin:string;builtin_key:string|null};
type DraftStep={title:string;description:string;command_refs:string;expected_observations:string;
  condition_kind:string;condition_value:string};
type Step={id:number;position:number;title:string;description:string;command_refs:string[];
  expected_observations:string[];status:string;result:string;notes:string;status_reason:string;
  outcome:string;guidance:{stage_id?:string;phase?:string;question?:string;purpose?:string;
    manual_checks?:string[];prerequisites?:string[];auth?:string;safety?:string};
  assessment:{summary?:string;facts?:Record<string,unknown>[];next_recommendations?:{
    step_id:number;position:number;title:string}[];raw_preserved?:boolean};
  evidence_ids:number[];execution_ids:number[];credential_ids:number[];condition_met:boolean;
  observations:{id:number;title:string;detail:string;status:string}[];
  timer_started_at?:string|null;elapsed_seconds?:number;
  node_key:string;node_type:string;activation:string;decision_trace:{kind?:string;reason?:string;
    label?:string;sources?:string[]}[];approval:{required?:boolean;reason?:string};
  approval_status:string;approval_reason:string;approved_by:string;attempts:number;last_error:string};
type Instance={id:number;project_id:number;target_id:number;service_id:number|null;
  template_name:string;target_name:string;service_name:string;status:string;
  progress:{completed:number;total:number;percent:number|null};steps?:Step[];
  workflow:{counts:Record<string,number>;active_step_ids:number[];active_node_keys:string[];
    blocked:number;excluded:number}};
type Recommendation={template_id:number;template_name:string;version_id:number;version:number;
  reasons:string[];applied:boolean;instance_id?:number|null;dismissed?:boolean};
type Evidence={id:number;title:string};
type Execution={id:number;service_id:number|null;template_id:string;status:string};
type Credential={id:number;username:string;secret_kind:string;secret_hint:string;domain:string;
  service_names:string[]};
type Summary={target_id:number;target_name:string;instances:number;steps:number;completed:number;
  percent:number|null;blocked:number;suspicious:number;last_activity:string|null;
  elapsed_seconds:number;stale:boolean};
type CredentialRecommendation={service_id:number;target_id:number;name:string;port:number;
  reason:string;source_service:boolean};
type Finding={id:number;title:string;description:string;status:string;observation_id:number};
type Activity={id:number;step_id:number|null;event_type:string;details:Record<string,unknown>;
  occurred_at:string};

const statuses=[
  "not_started","in_progress","completed","attempted","blocked","skipped",
  "suspicious","not_applicable",
];
const labels:Record<string,string>={
  not_started:"시작 전",in_progress:"진행 중",completed:"완료",attempted:"시도함",
  blocked:"차단됨",skipped:"건너뜀",suspicious:"의심",not_applicable:"해당 없음",
};
const activationLabels:Record<string,string>={
  ready:"실행 가능",waiting:"대기",running:"실행 중",completed:"완료",
  excluded:"현재 경로에서 제외",awaiting_approval:"승인 필요",retry_ready:"재시도 가능",
  review_required:"판정 필요",blocked:"차단",failed_handled:"오류 처리됨",
};
const activationLocked=new Set(["waiting","excluded","awaiting_approval"]);
const stepperCategory=(activation:string)=>{
  if(["completed","failed_handled"].includes(activation))return"done";
  if(["ready","running"].includes(activation))return"current";
  if(["awaiting_approval","retry_ready","review_required"].includes(activation))return"attention";
  if(activation==="blocked")return"blocked";
  if(activation==="excluded")return"excluded";
  return"waiting";
};
const emptyStep=():DraftStep=>({
  title:"",description:"",command_refs:"",expected_observations:"",
  condition_kind:"",condition_value:"",
});
const split=(value:string)=>value.split(",").map(item=>item.trim()).filter(Boolean);
const api=async<T,>(path:string,init?:RequestInit):Promise<T>=>{
  // The server sends Cache-Control: no-store, but responses fetched before
  // that shipped can still be sitting in the browser's disk cache (RFC 9110
  // allows heuristic caching of 404/410) and a page reload alone won't evict
  // them for in-app fetch() calls. Force every request past that cache.
  const response=await fetch("/api"+path,{cache:"no-store",...init});
  if(!response.ok){
    const body=await response.json().catch(()=>({}));
    throw new Error(body.detail||response.statusText);
  }
  return response.json();
};
const json=(body:unknown):RequestInit=>({
  method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body),
});

export default function RunbookWorkspace(){
  const qc=useQueryClient();
  const[view,setView]=useState<"library"|"instances">("instances");
  const[projectId,setProjectId]=useState(()=>Number(localStorage.getItem("oscp-workspace-project")));
  const[targetId,setTargetId]=useState<number>();
  const[serviceId,setServiceId]=useState<number>();
  const[selectedId,setSelectedId]=useState<number>();
  const autoApplyKey=useRef("");
  const[editing,setEditing]=useState(false);
  const[name,setName]=useState("");
  const[description,setDescription]=useState("");
  const[serviceNames,setServiceNames]=useState("");
  const[ports,setPorts]=useState("");
  const[draftSteps,setDraftSteps]=useState<DraftStep[]>([emptyStep()]);
  const[filter,setFilter]=useState("all");
  const[linkEvidence,setLinkEvidence]=useState("");
  const[linkExecution,setLinkExecution]=useState("");
  const[credentialUser,setCredentialUser]=useState("");
  const[credentialHint,setCredentialHint]=useState("");
  const[credentialRecommendations,setCredentialRecommendations]=useState<CredentialRecommendation[]>([]);
  const[toolsOpen,setToolsOpen]=useState(false);
  const[libraryMode,setLibraryMode]=useState<"scoped"|"all">("scoped");
  const[showExcluded,setShowExcluded]=useState(false);

  const projects=useQuery({queryKey:["projects"],queryFn:()=>api<Project[]>("/projects")});
  useEffect(()=>{
    if(!projectId&&projects.data?.length)setProjectId(projects.data[0].id);
  },[projectId,projects.data]);
  useEffect(()=>{
    const change=(event:Event)=>{
      const next=(event as CustomEvent<number>).detail;
      setProjectId(next);
      setTargetId(undefined);
      setServiceId(undefined);
      setSelectedId(undefined);
    };
    addEventListener("oscp-project-change",change);
    return()=>removeEventListener("oscp-project-change",change);
  },[]);
  const targets=useQuery({queryKey:["targets",projectId],
    queryFn:()=>api<Target[]>(`/targets?project_id=${projectId}`),enabled:!!projectId});
  useEffect(()=>{
    setTargetId(targets.data?.[0]?.id);
    setServiceId(undefined);
    setSelectedId(undefined);
  },[projectId,targets.data]);
  useEffect(()=>{
    if(targetId)dispatchEvent(new CustomEvent("oscp-target-change",{detail:targetId}));
  },[targetId]);
  const services=useQuery({queryKey:["services",targetId],
    queryFn:()=>api<Service[]>(`/targets/${targetId}/services`),enabled:!!targetId});
  useEffect(()=>setServiceId(services.data?.[0]?.id),[targetId,services.data]);
  useEffect(()=>{setLibraryMode("scoped");setEditing(false);},[targetId,serviceId]);
  const templates=useQuery({queryKey:["runbookTemplates"],
    queryFn:()=>api<Template[]>("/runbooks/templates")});
  const instances=useQuery({queryKey:["runbookInstances",targetId],
    queryFn:()=>api<Instance[]>(`/runbooks/instances?target_id=${targetId}`),enabled:!!targetId});
  const scopedInstances=(instances.data||[]).filter(item=>serviceId
    ?item.service_id===serviceId:item.service_id==null);
  useEffect(()=>{
    if(!scopedInstances.some(item=>item.id===selectedId))
      setSelectedId(scopedInstances[0]?.id);
  },[instances.data,serviceId,selectedId]);
  const selectedInstance=scopedInstances.find(item=>item.id===selectedId);
  const detail=useQuery({queryKey:["runbookInstance",targetId,selectedId],
    queryFn:()=>api<Instance>(`/runbooks/instances/${selectedId}`),enabled:!!selectedInstance,
    retry:5,retryDelay:attempt=>Math.min(500*(2**attempt),4000),refetchOnMount:"always"});
  const recommendations=useQuery({queryKey:["runbookRecommendations",targetId,serviceId],
    queryFn:()=>api<Recommendation[]>(serviceId
      ?`/runbooks/recommendations/${serviceId}`
      :`/runbooks/target-recommendations/${targetId}`),enabled:!!targetId});
  const evidence=useQuery({queryKey:["evidence",projectId],
    queryFn:()=>api<Evidence[]>(`/evidence?project_id=${projectId}`),enabled:!!projectId});
  const executions=useQuery({queryKey:["executions",targetId],
    queryFn:()=>api<Execution[]>(`/executions?target_id=${targetId}`),enabled:!!targetId});
  const credentials=useQuery({queryKey:["runbookCredentials",projectId],
    queryFn:()=>api<Credential[]>(`/runbooks/credentials?project_id=${projectId}`),enabled:!!projectId});
  const summaries=useQuery({queryKey:["runbookSummary",projectId],
    queryFn:()=>api<Summary[]>(`/runbooks/summary?project_id=${projectId}`),enabled:!!projectId});
  const findings=useQuery({queryKey:["runbookFindings",projectId],
    queryFn:()=>api<Finding[]>(`/runbooks/findings?project_id=${projectId}`),enabled:!!projectId});
  const activity=useQuery({queryKey:["runbookActivity",selectedId],
    queryFn:()=>api<Activity[]>(`/runbooks/instances/${selectedId}/activity`),enabled:!!selectedId});

  const refresh=async(_id?:number)=>{
    await Promise.all([
      qc.invalidateQueries({queryKey:["runbookInstances"]}),
      qc.invalidateQueries({queryKey:["runbookInstance"]}),
      qc.invalidateQueries({queryKey:["runbookRecommendations"]}),
      qc.invalidateQueries({queryKey:["runbookTemplates"]}),
      qc.invalidateQueries({queryKey:["runbookCredentials"]}),
      qc.invalidateQueries({queryKey:["runbookSummary"]}),
      qc.invalidateQueries({queryKey:["runbookFindings"]}),
      qc.invalidateQueries({queryKey:["runbookActivity"]}),
    ]);
  };
  const create=useMutation({
    mutationFn:async()=>{
      const template=await api<Template>("/runbooks/templates",json({
        name,description,service_names:split(serviceNames),
        ports:split(ports).map(Number),tags:[],
      }));
      return api(`/runbooks/templates/${template.id}/publish`,json({
        steps:draftSteps.map(step=>({
          title:step.title,description:step.description,
          command_refs:split(step.command_refs),
          expected_observations:split(step.expected_observations),
          condition:step.condition_kind?{
            kind:step.condition_kind,service_name:step.condition_value,
          }:{},
        })),
      }));
    },
    onSuccess:async()=>{
      setEditing(false);setName("");setDescription("");setServiceNames("");setPorts("");
      setDraftSteps([emptyStep()]);await refresh();
    },
  });
  const apply=useMutation({
    mutationFn:(versionId:number)=>api<Instance>("/runbooks/instances",json({
      version_id:versionId,target_id:targetId,service_id:serviceId||null,
    })),
    onSuccess:async row=>{setSelectedId(row.id);setView("instances");await refresh(row.id);},
    onError:()=>{autoApplyKey.current="";},
  });
  useEffect(()=>{
    if(view!=="instances"||!targetId||!serviceId||instances.isLoading||
      recommendations.isLoading||apply.isPending||scopedInstances.length)return;
    const candidate=recommendations.data?.find(item=>!item.applied);
    if(!candidate)return;
    const key=`${targetId}:${serviceId}:${candidate.version_id}`;
    if(autoApplyKey.current===key)return;
    autoApplyKey.current=key;
    apply.mutate(candidate.version_id);
  },[view,targetId,serviceId,instances.isLoading,recommendations.isLoading,
    recommendations.data,scopedInstances.length,apply.isPending]);
  const saveStep=useMutation({
    mutationFn:({step,status,result,notes,status_reason,outcome}:{
      step:Step;status:string;result:string;notes:string;status_reason:string;outcome:string;
    })=>api<Instance>(`/runbooks/steps/${step.id}`,{
      ...json({status,result,notes,status_reason,outcome}),method:"PATCH",
    }),
    onSuccess:row=>refresh(row.id),
  });
  const approveStep=useMutation({
    mutationFn:({step,decision,reason}:{step:Step;decision:"approved"|"rejected";reason:string})=>
      api<Instance>(`/runbooks/steps/${step.id}/approval`,json({decision,reason,actor:"local"})),
    onSuccess:row=>refresh(row.id),
  });
  const link=useMutation({
    mutationFn:({step,kind,id}:{step:Step;kind:"evidence"|"executions"|"credentials";id:number})=>
      api(`/runbooks/steps/${step.id}/${kind}`,json({resource_id:id})),
    onSuccess:()=>refresh(),
  });
  const createCredential=useMutation({
    mutationFn:()=>api("/runbooks/credentials",json({
      project_id:projectId,target_id:targetId||null,service_id:serviceId||null,
      username:credentialUser,secret_kind:"password",secret_hint:credentialHint,
      domain:"",service_names:serviceId?
        [services.data?.find(item=>item.id===serviceId)?.name||""]:[],notes:"",
    })),
    onSuccess:async()=>{setCredentialUser("");setCredentialHint("");await refresh();},
  });
  const exportTemplate=async(item:Template)=>{
    const data=await api(`/runbooks/templates/${item.id}/export`);
    const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:"application/json"}));
    const anchor=document.createElement("a");anchor.href=url;anchor.download=`${item.name}.runbook.json`;
    anchor.click();URL.revokeObjectURL(url);
  };
  const cloneTemplate=async(item:Template)=>{
    const cloneName=prompt("복제 Template 이름",`${item.name} copy`);
    if(!cloneName?.trim())return;
    await api(`/runbooks/templates/${item.id}/clone`,json({name:cloneName.trim()}));await refresh();
  };
  const archiveTemplate=async(item:Template)=>{
    if(!confirm(`${item.name}을 Library에서 보관 처리할까요? 기존 Instance는 유지됩니다.`))return;
    await api(`/runbooks/templates/${item.id}/archive`,json({}));await refresh();
  };
  const exportFindings=async()=>{
    const data=await api<{filename:string;markdown:string}>(
      `/runbooks/findings/export?project_id=${projectId}`);
    const url=URL.createObjectURL(new Blob([data.markdown],{type:"text/markdown"}));
    const anchor=document.createElement("a");anchor.href=url;anchor.download=data.filename;
    anchor.click();URL.revokeObjectURL(url);
  };
  const importTemplate=async(file:File)=>{
    const content=JSON.parse(await file.text());
    await api("/runbooks/templates/import",json(content));await refresh();
  };

  if(projects.isLoading)return <LoadingState label="Runbook 불러오는 중"/>;
  if(projects.error)return <ErrorState message="Runbook 데이터를 불러오지 못했습니다."/>;
  const activeDetail=detail.data?.target_id===targetId&&detail.data?.id===selectedId
    ?detail.data:undefined;
  const shown=(activeDetail?.steps||[]).filter(step=>(showExcluded||step.activation!=="excluded")&&
    (filter==="all"||step.status===filter));
  const currentSummary=summaries.data?.find(item=>item.target_id===targetId);
  const availableRecommendations=recommendations.data?.filter(item=>!item.applied)||[];
  const recommendationByTemplate=new Map(
    (recommendations.data||[]).map(item=>[item.template_id,item]),
  );
  const scopedTemplates=(templates.data||[]).filter(item=>
    recommendationByTemplate.has(item.id));
  const visibleTemplates=libraryMode==="all"?(templates.data||[]):scopedTemplates;
  const selectedService=services.data?.find(item=>item.id===serviceId);

  return <div className="runbookPage">
    <PageHeader title="Runbooks" actions={<nav className="runbookViews" aria-label="Runbook 보기">
        <Button variant={view==="instances"?"primary":"secondary"} onClick={()=>setView("instances")}>
          실행
        </Button>
        <Button variant={view==="library"?"primary":"secondary"} onClick={()=>setView("library")}>
          추천 Runbooks
        </Button>
      </nav>}/>

    <section className="runbookScope" aria-label="Runbook 범위">
      <label>Target<select value={targetId||""} onChange={event=>{
        setTargetId(Number(event.target.value));setServiceId(undefined);setSelectedId(undefined);
      }}>
        {targets.data?.map(item=><option key={item.id} value={item.id}>{item.name} · {item.ip}</option>)}
      </select></label>
      <label>Service<select value={serviceId||""} onChange={event=>setServiceId(Number(event.target.value))}>
        <option value="">Target 전체</option>
        {services.data?.map(item=><option key={item.id} value={item.id}>
          {item.port}/{item.protocol} · {item.name}
        </option>)}
      </select></label>
    </section>

    {view==="library"?<section className="runbookLibrary">
      <div className="runbookSectionTitle">
        <div><span>선택 범위에 맞춘 조사 절차</span><h2>{selectedService
          ?`${selectedService.port}/${selectedService.protocol} · ${selectedService.name} Runbooks`
          :"Target 공통 Runbooks"}</h2>
          <p>{libraryMode==="scoped"
            ?"탐지된 서비스와 일치하는 절차만 표시합니다. 미식별 서비스는 포트 번호를 보조 근거로 사용합니다."
            :"템플릿 관리용 전체 목록입니다. 현재 서비스 추천 목록이 아닙니다."}</p></div>
        <div className="libraryActions">
        <Button variant={libraryMode==="scoped"?"primary":"secondary"}
          onClick={()=>setLibraryMode("scoped")}>현재 범위 · {scopedTemplates.length}</Button>
        <Button variant={libraryMode==="all"?"primary":"secondary"}
          onClick={()=>setLibraryMode("all")}>전체 템플릿 관리 · {templates.data?.length||0}</Button>
        {libraryMode==="all"&&<><Button onClick={()=>setEditing(value=>!value)}>
          {editing?"작성 취소":"새 Template"}
        </Button>
        <label className="runbookImport">JSON 가져오기<input type="file" accept="application/json"
          onChange={event=>event.target.files?.[0]&&void importTemplate(event.target.files[0])}/></label></>}
        </div>
      </div>
      {editing&&<Card className="runbookEditor">
        <div className="runbookEditorGrid">
          <label>이름<input value={name} onChange={event=>setName(event.target.value)}/></label>
          <label>추천 서비스명<input value={serviceNames} onChange={event=>setServiceNames(event.target.value)}
            placeholder="smb, microsoft-ds"/></label>
          <label>추천 포트<input value={ports} onChange={event=>setPorts(event.target.value)}
            placeholder="139, 445"/></label>
          <label className="wide">설명<textarea value={description}
            onChange={event=>setDescription(event.target.value)}/></label>
        </div>
        <h3>단계</h3>
        {draftSteps.map((step,index)=><div className="draftStep" key={index}>
          <strong>{index+1}</strong>
          <label>제목<input value={step.title} onChange={event=>setDraftSteps(items=>
            items.map((item,i)=>i===index?{...item,title:event.target.value}:item))}/></label>
          <label>command ID<input value={step.command_refs} placeholder="smb-null-session"
            onChange={event=>setDraftSteps(items=>items.map((item,i)=>
              i===index?{...item,command_refs:event.target.value}:item))}/></label>
          <label className="wide">설명<textarea value={step.description}
            onChange={event=>setDraftSteps(items=>items.map((item,i)=>
              i===index?{...item,description:event.target.value}:item))}/></label>
          <label className="wide">예상 결과 (쉼표 구분)<input value={step.expected_observations}
            onChange={event=>setDraftSteps(items=>items.map((item,i)=>
              i===index?{...item,expected_observations:event.target.value}:item))}/></label>
          <label>활성 조건<select value={step.condition_kind}
            onChange={event=>setDraftSteps(items=>items.map((item,i)=>
              i===index?{...item,condition_kind:event.target.value}:item))}>
            <option value="">항상 활성</option>
            <option value="current_service_is">현재 Service 일치</option>
            <option value="service_exists">Project에 Service 존재</option>
            <option value="credential_exists">Credential 메타데이터 존재</option>
          </select></label>
          {step.condition_kind&&<label>조건 서비스명<input value={step.condition_value}
            placeholder="microsoft-ds" onChange={event=>setDraftSteps(items=>items.map((item,i)=>
              i===index?{...item,condition_value:event.target.value}:item))}/></label>}
          <div className="draftStepActions">
            <Button disabled={index===0} onClick={()=>setDraftSteps(items=>{
              const next=[...items];[next[index-1],next[index]]=[next[index],next[index-1]];return next;
            })}>↑</Button>
            <Button disabled={index===draftSteps.length-1} onClick={()=>setDraftSteps(items=>{
              const next=[...items];[next[index+1],next[index]]=[next[index],next[index+1]];return next;
            })}>↓</Button>
            <Button disabled={draftSteps.length===1}
              onClick={()=>setDraftSteps(items=>items.filter((_,i)=>i!==index))}>삭제</Button>
          </div>
        </div>)}
        {create.error&&<p className="runbookError" role="alert">{String(create.error)}</p>}
        <footer><Button onClick={()=>setDraftSteps(items=>[...items,emptyStep()])}>단계 추가</Button>
          <Button variant="primary" disabled={!name.trim()||draftSteps.some(step=>!step.title.trim())||create.isPending}
            onClick={()=>create.mutate()}>{create.isPending?"발행 중…":"Template 생성 및 v1 발행"}</Button>
        </footer>
      </Card>}
      <div className="runbookCards">
        {visibleTemplates.map(item=>{const relevance=recommendationByTemplate.get(item.id);return <Card key={item.id}
          className={relevance?"runbookTemplateRelevant":""}>
          <Badge status={item.latest_version?"completed":"pending"}>
            {item.builtin_key?`기본 · v${item.latest_version}`:
              item.latest_version?`사용자 · v${item.latest_version}`:"미발행"}
          </Badge>
          <h3>{item.name}</h3><p>{item.description||"설명 없음"}</p>
          <small>{item.service_names.join(", ")||"Target 전체"} · {item.ports.join(", ")||"포트 무관"}</small>
          {relevance&&<div className="templateRelevance"><strong>현재 범위와 일치</strong>
            <span>{relevance.reasons.map(reason=>reason
              .replace("detected-service:","탐지 서비스 · ")
              .replace("unidentified-port-fallback:","미식별 포트 보조 근거 · ")
              .replace("target:baseline","Target 공통 절차")).join(" · ")}</span></div>}
          <div className="templateActions">
            {relevance&&!relevance.applied&&item.latest_version_id&&<Button variant="primary"
              disabled={apply.isPending} onClick={()=>apply.mutate(item.latest_version_id!)}>이 Runbook 적용</Button>}
            {relevance?.applied&&relevance.instance_id&&<Button variant="primary" onClick={()=>{
              setSelectedId(relevance.instance_id!);setView("instances");
            }}>실행 화면 열기</Button>}
            {item.latest_version_id&&<Button onClick={()=>void exportTemplate(item)}>내보내기</Button>}
            {item.latest_version_id&&<Button onClick={()=>void cloneTemplate(item)}>복제</Button>}
            {!item.builtin_key&&<Button variant="quiet"
              onClick={()=>void archiveTemplate(item)}>보관</Button>}
          </div>
        </Card>})}
        {libraryMode==="scoped"&&!visibleTemplates.length&&<EmptyState
          title="이 범위에 맞는 Runbook이 없습니다"
          description="서비스 식별 결과를 보강하거나 Generic TCP 식별 절차를 적용하세요. 전체 템플릿은 관리 보기에서만 확인할 수 있습니다."/>}
      </div>
    </section>:<section className="runbookExecution">
      <aside>
        {!!availableRecommendations.length&&<div className="recommendations">
          <strong>추천</strong>
          {availableRecommendations.map(item=><button key={item.version_id} disabled={apply.isPending}
            onClick={()=>apply.mutate(item.version_id)}>
            <span>{item.template_name} · v{item.version}</span>
            <small>{serviceId?`${services.data?.find(service=>service.id===serviceId)?.port}번 Service`:
              "Target 전체"} · 적용</small>
          </button>)}
        </div>}
        {!scopedInstances.length?(availableRecommendations.length||apply.isPending
          ?<LoadingState label="서비스 Runbook 준비 중"/>
          :<EmptyState title="일치하는 Runbook 없음"
            description="서비스 식별 정보와 일치하는 조사 절차가 없습니다."/>):
          scopedInstances.map(item=><button className={selectedId===item.id?"active":""}
            key={item.id} onClick={()=>setSelectedId(item.id)}>
            <strong>{item.template_name}</strong>
            <span>{item.target_name}{item.service_name?` · ${item.service_name}`:""}</span>
            <progress max={100} value={item.progress.percent||0}/>
            <small>해당 단계 {item.progress.completed}/{item.progress.total}개 완료 · {item.progress.percent??"N/A"}%</small>
          </button>)}
      </aside>
      <main>
        {!selectedId?<EmptyState title="Runbook을 선택하세요"
          description="왼쪽 목록에서 실행할 Runbook을 선택하세요."/>:
        detail.isLoading||detail.isFetching&&!activeDetail?<LoadingState label="Runbook 단계 불러오는 중"/>:
        detail.error?<section className="runbookDetailError"><ErrorState message="Runbook 단계를 불러오지 못했습니다."/>
          <Button onClick={()=>void detail.refetch()}>다시 불러오기</Button></section>:
        activeDetail?<><header className="instanceHeader">
          <div><p>{activeDetail.target_name} {activeDetail.service_name&&`· ${activeDetail.service_name}`}</p>
            <h2>{activeDetail.template_name}</h2></div>
          <div className="instanceMetrics">
            <strong>{activeDetail.progress.percent??"N/A"}% 완료</strong>
            <span>해당 단계 {activeDetail.progress.total}개 중 {activeDetail.progress.completed}개 완료</span>
            {currentSummary&&<span>{Math.round(currentSummary.elapsed_seconds/60)}분</span>}
            {!!currentSummary?.blocked&&<span className="metricAttention">차단 {currentSummary.blocked}</span>}
            {!!currentSummary?.suspicious&&<span className="metricAttention">의심 {currentSummary.suspicious}</span>}
          </div>
        </header>
        {!!activeDetail.steps?.length&&<nav className="stepStepper" aria-label="단계 진행 개요">
          {[...activeDetail.steps].sort((a,b)=>a.position-b.position).map(step=>
            <button key={step.id} type="button"
              className={`stepStepperItem stepStepperItem--${stepperCategory(step.activation)}`}
              title={`${step.position}. ${step.title} · ${activationLabels[step.activation]||step.activation}`}
              onClick={()=>document.getElementById(`runbook-step-${step.id}`)
                ?.scrollIntoView({behavior:"smooth",block:"center"})}>
              {step.position}
            </button>)}
        </nav>}
        {activeDetail.progress.completed===0&&!(activeDetail.steps||[]).some(step=>step.execution_ids.length)&&
          <section className="runbookStartNotice"><strong>연결된 실행 결과 없음</strong></section>}
        <div className="instanceActions">
          <Button onClick={()=>setToolsOpen(value=>!value)}>
            {toolsOpen?"도구 닫기":"Credential · Finding"}
          </Button>
          {currentSummary?.stale&&<span className="staleFlag">30분 이상 활동 없음</span>}
        </div>
        {activeDetail.workflow&&<section className="workflowState" aria-label="현재 실행 경로">
          <strong>현재 경로</strong>
          {Object.entries(activeDetail.workflow.counts).filter(([,count])=>count>0).map(([state,count])=>
            <span key={state} className={`workflowState__${state}`}>
              {activationLabels[state]||state} {count}
            </span>)}
          {!!activeDetail.workflow.excluded&&<button onClick={()=>setShowExcluded(value=>!value)}>
            {showExcluded?"제외 단계 숨기기":`제외 단계 ${activeDetail.workflow.excluded}개 보기`}
          </button>}
        </section>}
        {toolsOpen&&<section className="runbookTools">
          <div className="credentialQuick">
            <strong>Credential</strong>
            <input value={credentialUser} aria-label="Credential 사용자명" placeholder="사용자명"
              onChange={event=>setCredentialUser(event.target.value)}/>
            <input value={credentialHint} aria-label="Credential 힌트" placeholder="비밀값 힌트"
              onChange={event=>setCredentialHint(event.target.value)}/>
            <Button disabled={!credentialUser.trim()||createCredential.isPending}
              onClick={()=>createCredential.mutate()}>추가</Button>
            {credentials.data?.map(item=><button key={item.id} onClick={async()=>{
              setCredentialRecommendations(await api(
                `/runbooks/credentials/${item.id}/recommendations`));
            }}>#{item.id} {item.username}</button>)}
            {credentialRecommendations.map(item=><small key={item.service_id}>
              {item.source_service?"출처":"재확인"} · {item.name}:{item.port}
            </small>)}
          </div>
          <div className="findingQuick">
            <strong>Findings <span>{findings.data?.length||0}</span></strong>
            {findings.data?.slice(0,5).map(item=><label key={item.id}>
              <span>{item.title}</span><select value={item.status} onChange={async event=>{
                await api(`/runbooks/findings/${item.id}`,{
                  ...json({title:item.title,description:item.description,status:event.target.value}),
                  method:"PATCH",
                });await refresh();
              }}><option value="candidate">candidate</option><option value="confirmed">confirmed</option>
                <option value="remediated">remediated</option>
                <option value="false_positive">false positive</option></select></label>)}
            {!!findings.data?.length&&<Button onClick={()=>void exportFindings()}>Markdown 내보내기</Button>}
          </div>
        </section>}
        <div className="stepFilters"><button className={filter==="all"?"active":""}
          onClick={()=>setFilter("all")}>전체</button>
          {["not_started","in_progress","suspicious","blocked","skipped"].map(status=>
            <button className={filter===status?"active":""} key={status}
              onClick={()=>setFilter(status)}>{labels[status]}</button>)}
        </div>
        <div className="instanceSteps">{shown.map(step=>
          <StepEditor key={step.id} step={step} saving={saveStep.isPending}
            onSave={(values)=>saveStep.mutate({step,...values})}
            onApprove={(decision,reason)=>approveStep.mutate({step,decision,reason})}
            evidence={evidence.data||[]} executions={(executions.data||[]).filter(item=>
              activeDetail.service_id?item.service_id===activeDetail.service_id:item.service_id==null)}
            credentials={credentials.data||[]}
            linkEvidence={linkEvidence} setLinkEvidence={setLinkEvidence}
            linkExecution={linkExecution} setLinkExecution={setLinkExecution}
            onLink={(kind,id)=>link.mutate({step,kind,id})}
            onRefresh={()=>refresh()}/>)}</div></>
        :<section className="runbookDetailError"><ErrorState message="선택한 Runbook 상세가 비어 있습니다."/>
          <Button onClick={()=>void detail.refetch()}>다시 불러오기</Button></section>}
        {!!activity.data?.length&&<details className="activityTimeline"><summary>Activity</summary>
          {activity.data.slice(0,30).map(item=><div key={item.id}>
            <time>{new Date(item.occurred_at).toLocaleString()}</time>
            <strong>{item.event_type.replaceAll("_"," ")}</strong>
            {item.step_id&&<small>Step #{item.step_id}</small>}
          </div>)}</details>}
      </main>
    </section>}
  </div>;
}

function StepEditor({step,saving,onSave,evidence,executions,linkEvidence,setLinkEvidence,
  linkExecution,setLinkExecution,onLink,credentials,onRefresh,onApprove}:{step:Step;saving:boolean;
  onSave:(values:{status:string;result:string;notes:string;status_reason:string;outcome:string})=>void;
  onApprove:(decision:"approved"|"rejected",reason:string)=>void;
  evidence:Evidence[];executions:Execution[];linkEvidence:string;
  credentials:Credential[];onRefresh:()=>void;
  setLinkEvidence:(value:string)=>void;linkExecution:string;setLinkExecution:(value:string)=>void;
  onLink:(kind:"evidence"|"executions"|"credentials",id:number)=>void}){
  const[status,setStatus]=useState(step.status);
  const[result,setResult]=useState(step.result);
  const[notes,setNotes]=useState(step.notes);
  const[reason,setReason]=useState(step.status_reason);
  const[outcome,setOutcome]=useState(step.outcome||"unknown");
  const[credentialId,setCredentialId]=useState("");
  const[observationTitle,setObservationTitle]=useState("");
  const[observationDetail,setObservationDetail]=useState("");
  const[approvalReason,setApprovalReason]=useState("");
  useEffect(()=>{setStatus(step.status);setResult(step.result);setNotes(step.notes);
    setReason(step.status_reason);setOutcome(step.outcome||"unknown");},[step]);
  const reasonNeeded=["blocked","skipped","not_applicable"].includes(status);
  const locked=activationLocked.has(step.activation);
  const traceReason=step.decision_trace?.find(item=>item.label||item.reason);
  const addObservation=async()=>{
    await api(`/runbooks/steps/${step.id}/observations`,json({
      title:observationTitle,detail:observationDetail,evidence_id:null,
    }));setObservationTitle("");setObservationDetail("");onRefresh();
  };
  const promote=async(observation:{id:number;title:string;detail:string})=>{
    await api(`/runbooks/observations/${observation.id}/promote`,json({
      title:observation.title,description:observation.detail,
    }));onRefresh();
  };
  const timer=async(action:"start"|"stop")=>{
    await api(`/runbooks/steps/${step.id}/timer/${action}`,json({}));onRefresh();
  };
  const assess=async()=>{
    if(!linkExecution)return;
    await api(`/runbooks/steps/${step.id}/assess-execution`,json({execution_id:Number(linkExecution)}));
    onRefresh();
  };
  return <Card id={`runbook-step-${step.id}`} className={`runbookStep runbookStep--${status} runbookStep--activation-${step.activation} ${!step.condition_met?"runbookStep--inactive":""}`}>
    <header><span>{String(step.position).padStart(2,"0")}</span>
      <div><h3>{step.title}</h3><p>{step.description}</p></div>
      <div className="stepState"><Badge status={step.activation}>{activationLabels[step.activation]||step.activation}</Badge>
        {step.activation==="completed"&&<small>{labels[status]}</small>}</div></header>
    {!step.condition_met&&<p className="conditionNotice">조건이 아직 충족되지 않아 진행률에서 제외됩니다.</p>}
    {traceReason&&<p className="branchReason">{traceReason.label||
      (traceReason.reason==="upstream_not_resolved"?"앞 단계의 판정을 기다리는 중":
       traceReason.reason==="another_branch_selected"?"다른 조사 경로가 선택됨":traceReason.reason)}</p>}
    {step.guidance?.question&&<details className="stepGuidance"><summary>목적·수동 확인</summary>
      <h4>{step.guidance.question}</h4>
      {!!step.guidance.prerequisites?.length&&<small>선행 조건 · {step.guidance.prerequisites.join(" · ")}</small>}
      {!!step.guidance.manual_checks?.length&&<ul>{step.guidance.manual_checks.map(item=><li key={item}>{item}</li>)}</ul>}
    </details>}
    {step.activation==="retry_ready"&&<div className="retryNotice"><strong>실행 오류 · 재시도 가능</strong>
      <span>{step.attempts}회 시도{step.last_error&&` · ${step.last_error}`}</span></div>}
    {step.activation==="awaiting_approval"&&<section className="approvalBox">
      <strong>실행 전 승인</strong><p>{step.approval.reason||"인증 정보 또는 영향 있는 작업을 사용합니다."}</p>
      <input value={approvalReason} placeholder="승인 또는 거절 사유" onChange={event=>setApprovalReason(event.target.value)}/>
      <div><Button variant="primary" disabled={!approvalReason.trim()}
        onClick={()=>onApprove("approved",approvalReason)}>승인</Button>
      <Button disabled={!approvalReason.trim()} onClick={()=>onApprove("rejected",approvalReason)}>거절</Button></div>
    </section>}
    {!!step.expected_observations.length&&<div className="expected"><strong>확인할 결과</strong>
      <ul>{step.expected_observations.map(item=><li key={item}>{item}</li>)}</ul></div>}
    {!!step.command_refs.length&&<div className="commands"><strong>권장 명령</strong>
      {step.command_refs.map(command=><code key={command}>{command}</code>)}
      <a href="#enumeration">Service Enumeration에서 검토 후 실행 →</a></div>}
    <fieldset className="stepFields" disabled={locked}>
      <label>상태<select value={status} onChange={event=>setStatus(event.target.value)}>
        {statuses.map(value=><option key={value} value={value}>{labels[value]}</option>)}
      </select></label>
      <label>조사 판정<select value={outcome} onChange={event=>setOutcome(event.target.value)}>
        <option value="unknown">미판정</option><option value="confirmed">확인됨</option>
        <option value="not_found">발견 안 됨</option><option value="access_denied">접근 거부</option>
        <option value="authentication_required">인증 필요</option><option value="partial">일부 확인</option>
        <option value="ambiguous">판정 불명확</option><option value="parser_failed">파싱 실패</option>
        <option value="needs_review">검토 필요</option><option value="error">오류</option>
        <option value="not_applicable">해당 없음</option></select></label>
      {reasonNeeded&&<label>사유<input value={reason} required onChange={event=>setReason(event.target.value)}/></label>}
      <label className="wide">결과<textarea value={result} onChange={event=>setResult(event.target.value)}/></label>
      <label className="wide">메모<textarea value={notes} onChange={event=>setNotes(event.target.value)}/></label>
    </fieldset>
    <div className="stepLinks">
      <label>Evidence<select value={linkEvidence} onChange={event=>setLinkEvidence(event.target.value)}>
        <option value="">Evidence 선택</option>{evidence.map(item=><option key={item.id} value={item.id}>
          #{item.id} {item.title}</option>)}</select>
        <Button disabled={!linkEvidence} onClick={()=>onLink("evidence",Number(linkEvidence))}>연결</Button></label>
      <label>Execution<select value={linkExecution} onChange={event=>setLinkExecution(event.target.value)}>
        <option value="">실행 결과 선택</option>{executions.map(item=><option key={item.id} value={item.id}>
          #{item.id} {item.template_id} · {item.status}</option>)}</select>
        <Button disabled={!linkExecution} onClick={()=>onLink("executions",Number(linkExecution))}>연결</Button></label>
      <Button disabled={!linkExecution} onClick={()=>void assess()}>원문 판정·연결</Button>
      <label>Credential<select value={credentialId} onChange={event=>setCredentialId(event.target.value)}>
        <option value="">Credential 선택</option>{credentials.map(item=><option key={item.id} value={item.id}>
          #{item.id} {item.domain&&`${item.domain}\\`}{item.username}</option>)}</select>
        <Button disabled={!credentialId} onClick={()=>onLink("credentials",Number(credentialId))}>연결</Button></label>
      <small>Evidence {step.evidence_ids.length} · Execution {step.execution_ids.length} · Credential {step.credential_ids.length}</small>
    </div>
    {step.assessment?.summary&&<section className="stepAssessment"><strong>실행 결과 판정 · {step.outcome}</strong>
      <p>{step.assessment.summary}</p>
      {!!step.assessment.facts?.length&&<small>구조화된 사실 {step.assessment.facts.length}개 · 원문 {step.assessment.raw_preserved?"보존됨":"확인 필요"}</small>}
      {!!step.assessment.next_recommendations?.length&&<ul>{step.assessment.next_recommendations.map(item=><li key={item.step_id}>
        다음 #{item.position} {item.title}</li>)}</ul>}
    </section>}
    <div className="observations">
      <strong>Observations</strong>
      {step.observations.map(item=><div key={item.id}><span>{item.title}</span>
        <small>{item.status}</small>{item.status==="open"&&<Button onClick={()=>void promote(item)}>
          Finding 후보로 승격</Button>}</div>)}
      <input value={observationTitle} placeholder="관찰 제목"
        onChange={event=>setObservationTitle(event.target.value)}/>
      <textarea value={observationDetail} placeholder="확인한 사실 또는 단서"
        onChange={event=>setObservationDetail(event.target.value)}/>
      <Button disabled={!observationTitle.trim()} onClick={()=>void addObservation()}>Observation 추가</Button>
    </div>
    <footer><Button variant="primary" disabled={locked||saving||(reasonNeeded&&!reason.trim())}
      onClick={()=>onSave({status,result,notes,status_reason:reason,outcome})}>
      {saving?"저장 중…":"단계 저장"}</Button>
      <Button onClick={()=>void timer(step.timer_started_at?"stop":"start")}>
        {step.timer_started_at?"타이머 중지":"타이머 시작"} · {Math.round((step.elapsed_seconds||0)/60)}분
      </Button></footer>
  </Card>;
}

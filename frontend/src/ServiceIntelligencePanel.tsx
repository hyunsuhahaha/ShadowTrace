type Match={key:string;name:string;level:string;score:number;reasons:string[]};
type Command={id:string;name:string;description:string;risk:string;completed:boolean;
  attempted?:boolean;outcome?:string;summary?:string};
type Stage={id:string;title:string;manual_checks:string[];auth:string;
  commands:Command[];completed:boolean;state:"observed"|"pending"|"review"|"failed"};
export type ServiceIntelligence={identity:{name:string;product:string;version:string;
  cpe:string[];tls:boolean};matches:Match[];stages:Stage[];attack_surface:string[];
  related_services:{service_id:number;name:string;port:number;protocol:string}[];
  runbooks:{name:string;version:number;version_id:number;applied:boolean;instance_id?:number}[];
  integration_counts:Record<string,number>};

const authLabel:Record<string,string>={anonymous:"익명 접근",optional:"인증 선택",required:"인증 필요",
  credential:"계정 필요",mixed:"익명·인증 비교",host:"호스트 권한"};

function stageStatus(stage:Stage){
  if(stage.completed)return "정보 확인";
  if(stage.state==="failed")return "실행 오류";
  if(stage.state==="review")return "판정 필요";
  if(stage.commands.length)return "미실행";
  return stage.id==="evidence"?"정리 필요":"수동 확인";
}
function stageTitle(stage:Stage){
  if(stage.id==="identity")return "서비스 식별";
  if(stage.id==="evidence")return "결과 정리";
  return stage.title;
}

export default function ServiceIntelligencePanel({data,loading,error,onRun}:{
  data?:ServiceIntelligence;loading:boolean;error:boolean;onRun:(id:string)=>void;
}){
  if(loading)return <section className="intelPanel intelPanel--loading">조사 단계 불러오는 중…</section>;
  if(error||!data)return <section className="intelPanel intelPanel--error">조사 단계를 불러오지 못했습니다.</section>;
  const completed=data.stages.filter(stage=>stage.completed).length;
  const profile=data.matches[data.matches.length-1]?.name||data.identity.name||"TCP";
  const identity=[data.identity.product,data.identity.version].filter(Boolean).join(" ");
  const linked=Object.entries(data.integration_counts).filter(([,value])=>value>0);
  const nextIndex=data.stages.findIndex(stage=>!stage.completed);
  return <section className="intelPanel" aria-labelledby="service-intelligence-heading">
    <header className="intelHeader"><div><h2 id="service-intelligence-heading">조사 단계</h2>
      <span>{profile}{identity&&` · ${identity}`}</span></div>
      <div className="intelProgress" aria-label={`${data.stages.length}단계 중 ${completed}단계 정보 확인`}>
        <b>{completed}/{data.stages.length}</b><small>정보 확인</small></div></header>
    <div className="intelStages">{data.stages.map((stage,index)=>{
      const status=stageStatus(stage);
      return <details key={`${stage.id}-${index}`} className={`intelStage ${stage.completed?"isComplete":""}`}
        open={!stage.completed&&index===nextIndex}>
        <summary><i>{stage.completed?"✓":String(index+1).padStart(2,"0")}</i>
          <b>{stageTitle(stage)}</b>{authLabel[stage.auth]&&<small>{authLabel[stage.auth]}</small>}
          <span>{status}</span></summary>
        <div className="intelStageBody">
          {!!stage.manual_checks.length&&<ul>{stage.manual_checks.map(item=><li key={item}>{item}</li>)}</ul>}
          {!!stage.commands.length&&<div className="intelCommands">{stage.commands.map(command=><button
            key={command.id} disabled={command.completed} onClick={()=>onRun(command.id)}>
            <b>{command.name}</b><span>{command.completed?"정보 확인":command.attempted?"다시 실행":"검토 후 실행"}</span>
            {command.summary&&<small>{command.summary}</small>}
          </button>)}</div>}
        </div></details>})}</div>
    {!!data.attack_surface.length&&<div className="intelSurface"><strong>확인 범위</strong>
      {data.attack_surface.map(item=><span key={item}>{item}</span>)}</div>}
    {(data.related_services.length>0||data.runbooks.length>0||linked.length>0)&&<footer className="intelFooter">
      {!!data.related_services.length&&<div><strong>관련 서비스</strong>{data.related_services.map(item=><span key={item.service_id}>
        {item.name} · {item.port}/{item.protocol}</span>)}</div>}
      {!!data.runbooks.length&&<div><strong>Runbook</strong>{data.runbooks.map(item=><a key={item.version_id}
        href="#runbooks">{item.name} · {item.applied?"적용됨":"적용"}</a>)}</div>}
      {!!linked.length&&<div className="intelIntegrations"><strong>연결됨</strong>{linked.map(([key,value])=><span key={key}>
        {key} {value}</span>)}</div>}
    </footer>}
  </section>;
}

import {lazy, Suspense, useEffect, useState} from "react";
import AppShell from "./AppShell";
import {LoadingState} from "./ui";

const Enumeration=lazy(()=>import("./App"));
const ScanCenter=lazy(()=>import("./ScanCenter"));
const WebWorkspace=lazy(()=>import("./WebWorkspace"));
const EvidenceWorkspace=lazy(()=>import("./EvidenceWorkspace"));
const DirectoryWorkspace=lazy(()=>import("./DirectoryWorkspace"));
const SessionWorkspace=lazy(()=>import("./SessionWorkspace"));
const ReportWorkspace=lazy(()=>import("./ReportWorkspace"));
const OperationsWorkspace=lazy(()=>import("./OperationsWorkspace"));
const ExploitResearchWorkspace=lazy(()=>import("./ExploitResearchWorkspace"));
const RunbookWorkspace=lazy(()=>import("./RunbookWorkspace"));
const PostExploitationWorkspace=lazy(()=>import("./PostExploitationWorkspace"));
const HashCrackingWorkspace=lazy(()=>import("./HashCrackingWorkspace"));
const ToolsWorkspace=lazy(()=>import("./ToolsWorkspace"));
const GraphWorkspace=lazy(()=>import("./features/graph/GraphWorkspace"));

// On the first load of a browser session, land on the Progress Graph (home)
// when the browser restored a stale workspace hash. An explicit Evidence link
// identifies one saved record and must remain usable in a fresh tab.
// Runs once at module import, before the component reads the hash — so no flash.
if (typeof sessionStorage !== "undefined" && !sessionStorage.getItem("oscp-home-shown")) {
  sessionStorage.setItem("oscp-home-shown", "1");
  if (location.hash && location.hash !== "#graph"
      && !/^#evidence\/[1-9]\d*\/[1-9]\d*$/.test(location.hash)
      && !/^#runbooks\/[1-9]\d*\/[1-9]\d*\/(?:0|[1-9]\d*)\/[1-9]\d*\/[1-9]\d*$/.test(location.hash)) location.hash = "#graph";
}

const route=()=>{
  const raw=location.hash.replace("#","")||"graph";
  const[page,...rest]=raw.split("/");
  return{page:page==="dashboard"?"graph":page,subroute:rest.join("/")||undefined};
};

export default function Root(){
  const[{page,subroute},setRoute]=useState(route());
  const[projectRevision,setProjectRevision]=useState(0);
  useEffect(()=>{
    const change=()=>setRoute(route());
    addEventListener("hashchange",change);
    return()=>removeEventListener("hashchange",change);
  },[]);
  useEffect(()=>{
    const change=()=>setProjectRevision((value)=>value+1);
    addEventListener("oscp-project-change",change);
    return()=>removeEventListener("oscp-project-change",change);
  },[]);
  let content;
  switch(page){
    case"enumeration":content=<><a className="backToScans" href="#scans">← Scan Center</a><Enumeration/></>;break;
    case"web":content=<WebWorkspace initialTab={subroute}/>;break;
    case"evidence":{
      const [target, evidence] = (subroute || "").split("/").map(Number);
      content=<EvidenceWorkspace initialTargetId={target || undefined}
        initialEvidenceId={evidence || undefined}/>;
      break;
    }
    case"directory":content=<DirectoryWorkspace/>;break;
    case"sessions":content=<SessionWorkspace/>;break;
    case"reports":content=<ReportWorkspace/>;break;
    case"operations":content=<OperationsWorkspace/>;break;
    case"exploit-research":content=<ExploitResearchWorkspace/>;break;
    case"runbooks":{
      const [projectId,targetId,serviceId,instanceId,stepId] = (subroute||"").split("/").map(Number);
      content=<RunbookWorkspace key={subroute} initialProjectId={projectId||undefined}
        initialTargetId={targetId||undefined} initialServiceId={serviceId||undefined}
        initialInstanceId={instanceId||undefined} initialStepId={stepId||undefined}/>;
      break;
    }
    case"post-exploitation":content=<PostExploitationWorkspace/>;break;
    case"hash-cracking":content=<HashCrackingWorkspace/>;break;
    case"tools":content=<ToolsWorkspace/>;break;
    case"graph":content=<GraphWorkspace/>;break;
    default:content=<ScanCenter/>;
  }
  return (
    <AppShell key={projectRevision} route={page}>
      <Suspense fallback={<LoadingState label="작업 공간 불러오는 중" />}>
        {content}
      </Suspense>
    </AppShell>
  );
}

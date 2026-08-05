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

const route=()=>{
  const raw=location.hash.replace("#","")||"scans";
  const[page,...rest]=raw.split("/");
  return{page:page==="dashboard"?"scans":page,subroute:rest.join("/")||undefined};
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
    case"enumeration":content=<><a className="backToScans" href="#">← Scan Center</a><Enumeration/></>;break;
    case"web":content=<WebWorkspace initialTab={subroute}/>;break;
    case"evidence":content=<EvidenceWorkspace/>;break;
    case"directory":content=<DirectoryWorkspace/>;break;
    case"sessions":content=<SessionWorkspace/>;break;
    case"reports":content=<ReportWorkspace/>;break;
    case"operations":content=<OperationsWorkspace/>;break;
    case"exploit-research":content=<ExploitResearchWorkspace/>;break;
    case"runbooks":content=<RunbookWorkspace/>;break;
    case"post-exploitation":content=<PostExploitationWorkspace/>;break;
    case"hash-cracking":content=<HashCrackingWorkspace/>;break;
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

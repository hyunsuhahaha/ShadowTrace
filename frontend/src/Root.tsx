import {lazy, Suspense, useEffect, useState} from "react";

const Enumeration=lazy(()=>import("./App"));
const ScanCenter=lazy(()=>import("./ScanCenter"));
const WebWorkspace=lazy(()=>import("./WebWorkspace"));
const EvidenceWorkspace=lazy(()=>import("./EvidenceWorkspace"));
const DirectoryWorkspace=lazy(()=>import("./DirectoryWorkspace"));
const SessionWorkspace=lazy(()=>import("./SessionWorkspace"));
const ReportWorkspace=lazy(()=>import("./ReportWorkspace"));
const OperationsWorkspace=lazy(()=>import("./OperationsWorkspace"));

const route=()=>location.hash.replace("#","")||"scans";

export default function Root(){
  const[page,setPage]=useState(route());
  useEffect(()=>{
    const change=()=>setPage(route());
    addEventListener("hashchange",change);
    return()=>removeEventListener("hashchange",change);
  },[]);
  let content;
  switch(page){
    case"enumeration":content=<><a className="backToScans" href="#">← Scan Center</a><Enumeration/></>;break;
    case"web":content=<WebWorkspace/>;break;
    case"evidence":content=<EvidenceWorkspace/>;break;
    case"directory":content=<DirectoryWorkspace/>;break;
    case"sessions":content=<SessionWorkspace/>;break;
    case"reports":content=<ReportWorkspace/>;break;
    case"operations":content=<OperationsWorkspace/>;break;
    default:content=<ScanCenter/>;
  }
  return <Suspense fallback={<div className="empty">Loading workspace…</div>}>{content}</Suspense>;
}

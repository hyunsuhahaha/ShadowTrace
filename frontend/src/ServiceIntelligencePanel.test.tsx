// @vitest-environment jsdom
import React from "react";
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {QueryClient,QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import ServiceIntelligencePanel, {type ServiceIntelligence} from "./ServiceIntelligencePanel";
import {api} from "./api";

vi.mock("./api",()=>({api:vi.fn()}));

const renderPanel=(node:React.ReactElement)=>render(
  <QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}>
    {node}
  </QueryClientProvider>,
);

afterEach(cleanup);

it("shows completed execution state without explanatory filler",()=>{
  const data:ServiceIntelligence={
    identity:{name:"msrpc",product:"Microsoft Windows RPC",version:"",cpe:[],tls:false},
    matches:[{key:"windows_rpc",name:"Microsoft RPC Endpoint Mapper",level:"protocol",score:90,reasons:[]}],
    stages:[
      {id:"identity",title:"정확한 서비스 식별",manual_checks:[],auth:"none",state:"observed",
        completed:true,commands:[{id:"service-version",name:"제품·버전 식별",description:"",risk:"low",completed:true}]},
      {id:"rpc-endpoints",title:"RPC 인터페이스와 Endpoint 열거",manual_checks:["UUID 확인"],
        auth:"none",state:"pending",completed:false,commands:[{id:"msrpc-enum",name:"RPC 인터페이스 열거",description:"",risk:"low",completed:false}]},
    ],
    attack_surface:[],related_services:[],runbooks:[],integration_counts:{},
  };
  renderPanel(<ServiceIntelligencePanel data={data} loading={false} error={false} onRun={vi.fn()}/>);
  expect(screen.getByLabelText("2단계 중 1단계 정보 확인")).toBeTruthy();
  expect(screen.getByText("서비스 식별")).toBeTruthy();
  expect(screen.getByText("미실행")).toBeTruthy();
  expect(document.querySelectorAll(".intelPanel p")).toHaveLength(0);
  expect(document.body.textContent).not.toContain("포트 추측이 아니라");
});

it("shows a semantically empty completed process as review instead of done",()=>{
  const data:ServiceIntelligence={
    identity:{name:"msrpc",product:"Microsoft Windows RPC",version:"",cpe:[],tls:false},
    matches:[{key:"windows_rpc",name:"Microsoft RPC Endpoint Mapper",level:"protocol",score:90,reasons:[]}],
    stages:[{id:"rpc-endpoints",title:"RPC 인터페이스와 Endpoint 열거",manual_checks:[],auth:"none",
      state:"review",completed:false,commands:[{id:"msrpc-enum",name:"RPC 인터페이스 열거",
        description:"",risk:"low",completed:false,attempted:true,outcome:"needs_review",
        summary:"명령은 종료됐지만 RPC endpoint는 반환되지 않았습니다."}]}],
    attack_surface:[],related_services:[],runbooks:[],integration_counts:{},
  };
  renderPanel(<ServiceIntelligencePanel data={data} loading={false} error={false} onRun={vi.fn()}/>);
  expect(screen.getByText("판정 필요")).toBeTruthy();
  expect(screen.getByText("다시 실행")).toBeTruthy();
  expect(screen.getByText("명령은 종료됐지만 RPC endpoint는 반환되지 않았습니다.")).toBeTruthy();
});

it("opens the latest command output inline and closes it explicitly",async()=>{
  vi.mocked(api).mockResolvedValue({stdout:"PORT 80/tcp open http",status:"completed"});
  const data:ServiceIntelligence={
    identity:{name:"http",product:"Apache",version:"2.4.38",cpe:[],tls:false},
    matches:[],stages:[{id:"identity",title:"서비스 식별",manual_checks:[],auth:"none",
      state:"observed",completed:true,commands:[{id:"http-methods",name:"HTTP 허용 메서드",
        description:"",risk:"low",completed:true}]}],attack_surface:[],related_services:[],
    runbooks:[],integration_counts:{},
  };
  renderPanel(<ServiceIntelligencePanel data={data} loading={false} error={false}
    onRun={vi.fn()} executions={[{id:10,template_id:"http-methods",status:"completed",command:"nmap"}]}/>);
  fireEvent.click(screen.getByText("HTTP 허용 메서드"));
  await waitFor(()=>expect(screen.getByText("PORT 80/tcp open http")).toBeTruthy());
  expect(api).toHaveBeenCalledWith("/executions/10/output");
  expect(document.querySelector(".intelInlineOutput")).toBeTruthy();
  fireEvent.click(screen.getByRole("button",{name:"결과 닫기"}));
  expect(screen.queryByText("PORT 80/tcp open http")).toBeNull();
});

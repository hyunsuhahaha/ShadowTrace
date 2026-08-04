import {expect,it} from "vitest";
import {parseWebLaunchContext} from "./WebWorkspace";

it("accepts only a complete HTTP service launch context",()=>{
  expect(parseWebLaunchContext(JSON.stringify({
    targetId:12,serviceId:80,url:"http://10.129.225.252/",
  }))).toEqual({targetId:12,serviceId:80,url:"http://10.129.225.252/"});
  expect(parseWebLaunchContext('{"targetId":12,"url":"file:///tmp/x"}')).toBeUndefined();
});

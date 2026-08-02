import {useQuery} from "@tanstack/react-query";
import {api} from "./api";
import type {ServiceIntelligence} from "./ServiceIntelligencePanel";
import type {Project, Service, Target} from "./enumerationModel";

export function useEnumerationQueries({
  projectId,
  targetId,
  serviceId,
}: {
  projectId?: number;
  targetId?: number;
  serviceId?: number;
}) {
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Project[]>("/projects"),
  });
  const targets = useQuery({
    queryKey: ["targets", projectId],
    queryFn: () => api<Target[]>(`/targets?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const services = useQuery({
    queryKey: ["services", targetId],
    queryFn: () => api<Service[]>(`/targets/${targetId}/services`),
    enabled: !!targetId,
  });
  const commands = useQuery({
    queryKey: ["commands", serviceId],
    queryFn: () => api<any[]>(`/services/${serviceId}/commands`),
    enabled: !!serviceId,
  });
  const intelligence = useQuery({
    queryKey: ["serviceIntelligence", serviceId],
    queryFn: () => api<ServiceIntelligence>(
      `/services/${serviceId}/intelligence`,
    ),
    enabled: !!serviceId,
  });
  const targetCommands = useQuery({
    queryKey: ["targetIdentityCommands", targetId],
    queryFn: () => api<any[]>(`/targets/${targetId}/identity-commands`),
    enabled: !!targetId,
  });
  const executions = useQuery({
    queryKey: ["executions", targetId],
    queryFn: () => api<any[]>(`/executions?target_id=${targetId}`),
    enabled: !!targetId,
  });

  return {
    projects,
    targets,
    services,
    commands,
    intelligence,
    targetCommands,
    executions,
  };
}

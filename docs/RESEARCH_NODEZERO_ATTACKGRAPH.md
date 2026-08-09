# Research: Horizon3.ai NodeZero AttackGraph data model

**Purpose:** Design benchmark for our OSCP lab progress-tracker graph model. This is a
design/architecture study of a published API, unrelated to any exam-time tooling.

**Scope of sources:** PRIMARY (first-party) only. The Horizon3 GraphQL API reference page
is a single, static (server-rendered) HTML document — it is NOT JS-gated and was fully
readable. All schema claims below come from that page unless marked otherwise.

- Primary source (canonical): `https://docs.horizon3.ai/api/graphql/`
  - Mirror with identical content: `https://docs.horizon3.ai/reference/api/reference/graphql/`
  - The page uses per-type anchors, e.g. `#definition-AttackGraph`, `#definition-Node`,
    `#definition-Edge`, `#definition-AttackVector`, `#definition-AttackPath`,
    `#definition-Host`, `#definition-Service`, `#definition-Weakness`,
    `#definition-Credential`, `#definition-ImpactType`.

**Verification legend:** [V] = verbatim from the GraphQL schema reference (verified fact);
[I] = inference drawn from primary text; [D] = documentation discrepancy noted.

---

## 0. How the graph is organized (orientation)

The attack graph is not a top-level object. It is nested:

`AttackPath` → `AttackVector` → `AttackGraph` → `Node[]` + `Edge[]`.
[V] `https://docs.horizon3.ai/api/graphql/#definition-AttackPath`

- **AttackPath** — "represents the sequence of steps NodeZero took to achieve a specific
  Impact during a pentest. Each AttackPath links to a target Impact and includes the
  exploited Weaknesses, compromised Credentials, and traversed Hosts." [V]
- **AttackVector** — "a directed acyclic graph (DAG) of Nodes and Edges that represents the
  step-by-step attack path NodeZero took to reach a target entity." Has
  `target_node - Node!` (the final entity reached) and `attack_graph - AttackGraph`. [V]
  `#definition-AttackVector`
- **AttackGraph** — "the directed acyclic graph (DAG) structure within an AttackVector,
  comprising the set of Nodes and Edges that represent the attack path." Fields:
  `nodes - [Node]`, `edges - [Edge]`. [V] `#definition-AttackGraph`

The same graph can be rendered by different **algorithms** (`AttackVectorAlgorithm` enum):
`POC` (a.k.a. `v1`, most detailed, nothing pruned), `v2` (retired), `v3` (streamlined into
chronological timestep layers), `v4` (most consolidated). [V]
`#definition-AttackVectorAlgorithm`

---

## 1. Node types and their attributes

### Key architectural fact
The AttackGraph has exactly **one node GraphQL type: `Node`**. It is a *wrapper* that carries
attack-vector context around an underlying "target entity." It is NOT one class per entity
kind. [V] `#definition-Node`:
> "A Node wraps attack-vector context around a target entity such as a Host, Weakness,
> Credential, or service that NodeZero discovered or exploited during its attack path."

The AttackGraph description enumerates what nodes represent: "the hosts, services,
**Weaknesses**, **Credentials**, and other entities that NodeZero discovered and exploited."
[V] `#definition-AttackGraph`

`Node` exposes typed accessors to only three underlying entity records:

| Node accessor | Type | Meaning |
|---|---|---|
| `host` | `Host` | present if the node represents an endpoint/network address [V] |
| `weakness` | `Weakness` | present if the node represents an exploited vulnerability [V] |
| `credential` | `Credential` | present if the node represents a compromised/potential credential [V] |

There is **no `Node.service` accessor** even though the prose lists services — a Service is
reachable via `Weakness.affected_service` or `Host`, not directly off a `Node`. [V][D]

**Other node kinds exist in the raw POC/v1 graph but are pruned in v3/v4:** "Impact and proof
nodes are removed and surfaced as labels on their connected nodes. AWS Connection nodes are
removed." So the full graph also contains **Impact nodes, Proof nodes, and AWS Connection
nodes**. [V] `#definition-AttackVectorAlgorithm` (v3 value)

#### `Node` attributes (verbatim field list) [V]
- `uuid - String!` — node id; referenced by `Edge.from_uuid` / `Edge.to_uuid`
- `attack_vector_node_uuid - String!` — id of the underlying AVNode record
- `found_by_module_meta - ModuleMeta` — the NodeZero module that discovered the node
  (name, category, MITRE ATT&CK mappings)
- `found_by_module_instance - ModuleInstance` — the specific module run (action logs,
  executed commands, MITRE mapping)
- `score - Float` — cyber-risk score 0–10
- `severity - Severity`
- `proofs - [Proof]` — evidence captured at this step
- `time_to_finding - String` — elapsed time from pentest start, `HH:MM:SS`
- `label_line1 / label_line2 / label_line3 - String` — render labels (used in v3/v4)
- `icon_label - String` — the action performed, e.g. "Found Host", "Exploited Weakness"
- `description - String` — human-readable action description
- `subflow_nodes - [Node]` — downstream nodes in the same timestamp layer
- `weakness - Weakness`, `credential - Credential`, `host - Host` — typed entity accessors

> **Modules / operations are NOT separate node types.** An action/operation is captured as
> attributes of a node: `icon_label` (the action verb) plus `found_by_module_meta` /
> `found_by_module_instance` (the module and its MITRE mapping and command logs). [V][I]

### Underlying entity types (referenced by nodes)

**`Host`** [V] `#definition-Host`: `uuid`, `created_at`, `ip`, `mac`, `cname_chains`,
`host_name`, `host_names`, `is_in_scope`, `is_domain_controller`, `is_database_server`,
`is_load_balancer`, `is_mail_server`, `is_vpn`, `is_waf`, `os_fingerprints`,
`hardware_fingerprints`, `device_fingerprints`, `os_names`, `subnet`, `cloud_provider`,
`cloud_region`, `cloud_arns`, `is_public`, `score`, `severity`, counts for
services/credentials/data-stores/weaknesses/attack-paths, `portal_url`.

**`Service`** [V] `#definition-Service`: `uuid`, `created_at`, `ip!`, `port!`, `protocol`,
`fingerprints`, `iana_service_name`, `host - Host`, `data_resources_count`,
`web_resources_count`, `score`, `severity`, `context_score_description`, `op_id`.

**`Weakness`** [V] `#definition-Weakness`: `uuid`, `created_at`, `vuln_id`, `vuln - Vuln!`,
`vuln_aliases`, `vuln_category`, `vuln_name`, `vuln_cisa_kev`,
`vuln_known_ransomware_campaign_use`, `ip`, `has_proof`, `proof_failure_code/reason`,
`score`, `severity`, `base_score/base_severity`, `context_score/context_severity`,
`context_score_description(_md)`, `time_to_finding_hms/_s`, `affected_asset_display_name`,
`downstream_impact_types - [ImpactType!]`, `attack_paths_count`, `mitre_mappings`,
`proofs`, and a family of typed **affected-asset accessors**: `affected_host`,
`affected_service`, `affected_application`, `affected_cloud_resource`, `affected_cloud_role`,
`affected_external_domain`, `affected_interesting_resource`, `affected_ldap_domain`,
`affected_data_store`. These accessor types (Application, CloudResource, CloudRole,
ExternalDomain, LDAPDomain, InterestingResource, DataStore) are the fuller entity taxonomy
of the platform, though only Host/Weakness/Credential surface directly on graph `Node`. [V]

**`Credential`** [V] `#definition-Credential`: `uuid`, `created_at`, `cred_type`,
`user_name`, `k8s_identity_name`, `cloud_role_name`, `cloud_account_id`, `ip`/`ips`,
`sockets`, `product`, `permissions_list`, `api_key_id`, `api_secret_key`,
`api_session_token`, `cleartext`, `hash`, `is_validated`, `hosts - [Host]`, `is_injected`,
`is_cracked`, `is_local_admin`, `is_domain_admin`, `is_entra_global_admin`, `role_name`,
`score`, `severity`, `weaknesses_count`, `services_count`, `data_stores_count`,
`downstream_impact_types`, `attack_paths_count`, `time_to_finding_hms/_s`, `display_name`,
`portal_url`.

---

## 2. What the edges represent (direction & semantics)

`Edge` is a minimal, **untyped, directed** connector. [V] `#definition-Edge`
> "An edge in an AttackVector graph. Connects two Nodes in the directed acyclic graph (DAG):
> the source (from) node and the target (to) node. Each edge represents a single step in the
> attack path that NodeZero traversed."

Fields (verbatim): `from_uuid - String!` (source `Node.uuid`), `to_uuid - String!` (target
`Node.uuid`). [V]

- **Direction:** explicit, `from → to`, source → target. [V]
- **Semantics:** "a single step in the attack path." Edges carry **no relation label, no
  type, no weight** — the *meaning* of a step lives on the destination node (`icon_label`,
  `found_by_module_meta`, `description`), not on the edge. [V][I]
- Ordering/sequence is expressed by edges plus the node timeline fields, not by an edge
  property. [I]

---

## 3. Is it a DAG?

**Yes — stated explicitly and repeatedly (verified, not inferred).** [V]
- `#definition-AttackGraph`: "An AttackGraph is the directed acyclic graph (DAG) structure…"
- `#definition-AttackVector`: "a directed acyclic graph (DAG) of Nodes and Edges…"
- `#definition-Edge`: "Connects two Nodes in the directed acyclic graph (DAG)…"
- `#definition-AttackPath`: `attack_vector` provides "the full directed acyclic graph (DAG)
  of Nodes and Edges…"

---

## 4. Layer / time / temporal / depth field for timeline rendering

**Yes.** The model has both a per-node elapsed-time value and an explicit layered timeline
structure.

- `Node.time_to_finding - String` — "elapsed time from the start of the pentest to when
  NodeZero discovered this node. Formatted as `HH:MM:SS`." [V] `#definition-Node`
- **Layered timeline (the depth/timestep concept):** [V] `#definition-AttackGraph`
  > "The attack path can be organized into layers, where each layer represents a distinct
  > time step… All nodes in the same layer were discovered or exploited at the same time.
  > The layers can be used to render the graph as a timeline showing the progression of the
  > attack."
- `Node.subflow_nodes - [Node]` — "Downstream nodes… that occurred at the same time as this
  node. These nodes are grouped in the same timestamp layer… rendered alongside this node in
  v3 and v4." [V]
- **v3 algorithm** materializes the layers: "structured chronologically by timestep 'layers'.
  All nodes created at the same time are grouped into the same layer. The first node in each
  layer remains in the main graph; subsequent nodes are stored as `subflow_nodes` of that
  first node. This structure facilitates rendering the graph on a timeline, as it appears in
  the Portal." [V] `#definition-AttackVectorAlgorithm`

**[D] Documentation discrepancy to flag:** The AttackGraph prose says "Each node is
associated with a layer via `Node.layer_label`," but **`layer_label` does NOT appear in the
documented `Node` field list** (nor in any example fragment). So a per-node layer *concept*
is documented, but a queryable `Node.layer_label` field could not be verified from the schema
reference. In practice the layer is realized structurally via `subflow_nodes` + the v3
algorithm and `time_to_finding`. Treat `Node.layer_label` as documented-but-unverified.

---

## 5. Explicit objective / critical asset / target / goal representation

**Yes — the objective is a first-class concept, modeled as the "Impact" and the target node.**
[V]

- `AttackVector.target_node - Node!` — "the final entity that NodeZero reached at the end of
  this attack path." [V] `#definition-AttackVector`
- `AttackPath` is defined *by* its objective: it "links to a target **Impact**," exposes
  `impact_type - ImpactType!` (e.g. `DomainCompromise`, `RansomwareExposure`),
  `impact_title`, `impact_description`, `affected_asset_text`, and `created_at` = "when the
  target Impact was achieved." [V] `#definition-AttackPath`
- **Impact nodes are literal nodes in the raw POC graph** and are "removed and surfaced as
  labels on their connected nodes" only in the streamlined v3/v4 renderings. So at the base
  layer the goal is an actual graph node. [V] `#definition-AttackVectorAlgorithm`
- Docs framing (first-party, same site): AttackPaths "show how NodeZero compromised critical
  assets… understand the complete kill chain from initial access to objective." [V]
  `https://docs.horizon3.ai/api/graphql/` (Impacts section intro)
- Criticality is scored: an Impact with context-adjusted score ≥ 9.0 is "Critical Severity."
  [V]

---

## 6. Comparison table: NodeZero vs. OUR model

### Node types

| Our node | NodeZero equivalent | Alignment |
|---|---|---|
| `project-root` | (no direct equivalent; nearest is the `Op`/pentest + the entry `Host` node) | Differs — NodeZero has no single root node; the graph is per-AttackVector, rooted at first discovery |
| `host` | `Host` (via `Node.host`) | Strong align |
| `service` | `Service` (entity exists; **not** a direct graph-node accessor) | Partial — they model Service as an entity but surface it through Host/Weakness, not as a first-class graph node |
| `finding` | `Weakness` (via `Node.weakness`) | Strong align (they add rich CVE/MITRE/CISA-KEV metadata) |
| `technique` | **No node.** Captured as node attributes: `icon_label` + `found_by_module_meta`/`found_by_module_instance` (MITRE mapping) | **Key divergence — see note below** |
| `credential` | `Credential` (via `Node.credential`) | Strong align (they add `is_domain_admin`, `is_cracked`, `is_injected`, etc.) |
| — | `Impact` node / `target_node` (the objective) | **We lack this — candidate to adopt** |
| — | `Proof` node, `AWS Connection` node (POC graph only) | We have no direct analog (Proof is closest to our evidence handling) |

### Edge relations

| Our edge | NodeZero equivalent | Alignment |
|---|---|---|
| `discovered`, `enumerated`, `attempted`, `yielded`, `pivoted-to`, `reused-credential`, `blocked-by` | A single untyped directed `Edge` (`from_uuid → to_uuid`) meaning "one step in the path" | **Major divergence.** We put semantics on the edge (7 typed relations). NodeZero puts semantics on the destination *node* (`icon_label`, `description`, module/MITRE). Their edges are pure sequence. |

Note: our `blocked-by` (a failed/blocked attempt) has no NodeZero graph analog — their
AttackGraph is a success-path DAG; failure info lives on `Weakness.proof_failure_code` /
`proof_failure_reason`, not as an edge.

### What WE could adopt

1. **An objective / critical-asset node (highest value).** NodeZero makes the goal explicit
   (`target_node` + `Impact` + `ImpactType` like DomainCompromise/RansomwareExposure, with a
   context-adjusted criticality score). Our six node types have no goal node. Adopting an
   `objective`/`impact` node (or at least an "is-target" marker + criticality score on a
   host/finding) would let us render "path to goal" and rank paths by business impact.
2. **A layer / timestep field for timeline rendering.** NodeZero groups same-time nodes into
   ordered layers (`subflow_nodes`, the v3 timestep model) plus per-node `time_to_finding`
   (`HH:MM:SS`). Adding an explicit `layer`/`depth` (or discovery-timestamp) to our nodes
   would give us the same "timeline of the attack" rendering essentially for free.
3. **Provenance on nodes:** their `found_by_module_meta` / `found_by_module_instance` ties
   each node to the tool run + MITRE ATT&CK mapping + command logs. Our `technique` node
   already captures the "how"; we could additionally stamp each node with the technique/tool
   that produced it (provenance) even where technique stays its own node.
4. **Path complexity/score rollups:** `AttackVector.total_score` / `max_score`,
   `nodes_count`, `credentials_count`, `weaknesses_count`, `hosts_count`, and a `narrative`
   subset — cheap derived summaries worth mirroring on our derived Attack Path.

### Deliberate design divergences (ours, on purpose — not gaps to close)

- **We model `technique` as a NODE, NodeZero models it as edge/node metadata.** NodeZero
  keeps the graph to entities (host/weakness/credential/impact) and hangs the technique off
  the node as `icon_label` + module/MITRE metadata. We intentionally promote Technique to a
  first-class node so techniques are queryable, reusable across paths, and linkable to
  multiple findings. This is a conscious modeling choice, not a shortfall.
- **We allow CYCLES in the working graph; NodeZero's AttackGraph is a strict DAG.** Our live
  working graph tolerates cycles (e.g. credential reuse looping back to an earlier host,
  re-enumeration). We then DERIVE an acyclic Attack Path (a DAG) for reporting. NodeZero only
  ever exposes the derived DAG. So our working graph is intentionally more permissive; our
  *derived* artifact matches their DAG guarantee.

---

## 7. What could NOT be verified from primary sources

- **`Node.layer_label`** — referenced in AttackGraph prose but absent from the documented
  `Node` field list and all example fragments. Layer semantics are otherwise realized via
  `subflow_nodes` + the v3 algorithm + `time_to_finding`. [D]
- **Full field lists for the secondary affected-asset types** (Application, CloudResource,
  CloudRole, ExternalDomain, LDAPDomain, InterestingResource, DataStore) were not exhaustively
  transcribed here; they exist as `Weakness.affected_*` accessors on the same page and were
  confirmed present, but only Host/Service/Weakness/Credential were captured field-by-field
  per the task's emphasis.
- **No engineering-blog post** on `horizon3.ai` was needed or used; every load-bearing claim
  came from the GraphQL API reference itself, so no secondary sources are cited. If deeper
  rendering/UX detail is wanted, the Portal-facing product pages under `horizon3.ai/nodezero/`
  would be the next first-party stop (not consulted here).

---

*Compiled from Horizon3.ai first-party GraphQL API reference. Not committed to git.*

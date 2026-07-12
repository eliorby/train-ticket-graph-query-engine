# Train Ticket Graph Query Engine - Design Doc

## 1. Overview

This service loads a static JSON graph describing the Train Ticket microservices architecture
(services, an RDS instance, an SQS queue, and the edges between them)
and exposes it through a generic, filterable query engine over a REST API.

The core idea is to find **multi-hop routes** through the graph that match
a composable set of security-relevant conditions - 
i.e. routes that start at a public-facing service, pass through a node with a
known vulnerability, and terminate at a sensitive sink (a database or queue).

This is a small, self-contained version of attack-path / toxic-flow analysis:
given a system graph, find the paths an attacker (or a bug) could actually travel
from exposure to impact.

## 2. Exercise Analysis

### 2.1 Problem Interpretation

The assignment gives three filter conditions - 
public source, vulnerable node, sink destination - 
and asks for a generic, extensible filtering mechanism over routes.

This clearly meant to answer a security question: **can something reachable
from the outside world get to a sensitive resource through a weak point?**

Each filter alone answers a *different* real security question
(attack surface mapping / vulnerability triage / data-exposure mapping).

That's the interpretation this design follows throughout -
the API isn't just "filter the graph," it's
"find candidate attack paths in the graph, with filters as the building blocks".

### 2.2 Key Interpretive Decisions

|                                              | Interpretive Decision                                                                                                                                     |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `route` definition                           | A simple **N-hop path** (no repeated nodes within the same route), between any two nodes in the graph.                                                    |
| Combining multiple filters in a single query | **AND logic** - together they answer "where's the actual exploitable path". Running filters individually already produces the broader, independent views. |
| `sink` classification                        | Derived, not hardcoded: **any node where `kind != "service"`** (currently `rds`, `sqs`), with an optional `sinkKinds` filter param to narrow further.     |
| vulnerable `node` definition                 | A node with a **non-empty `vulnerabilities` array**, at **any** severity (a `minSeverity` threshold was considered and deferred).                         |
| Edge `to` values                             | Treated as an unordered set of target node names.                                                                                                         |

### 2.3 Problems found in source data & How I handled them

| Source Data Issue                                                                                                                     | Handling Decision                                                                                                                                                |
|---------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Edge` `to` field shape inconsistency                                                                                                 | This is a parsing concern → silently normalize (string → single-element array).                                                                                  |
| Dangling node references - missing from `nodes` but referenced `edges` (i.e. `assurance-service`)                                     | This is a data-integrity concern → flag.                                                                                                                         |
| `Vulnerability` fields mismatch: `message` and `metadata.cwe` (SQL-injection-flavored `message` tagged with `CWE-22: Path Traversal`) | `message` and `severity` are treated as the authoritative vulnerability description.<br/>`metadata.cwe` is passed through as-is and not used for classification. |

### 2.4 Out of Scope

The following are explicitly left out of the implementation:

- **API AuthN/AuthZ** - this service exposes infrastructure topology and
  known vulnerabilities, which is itself sensitive.
  In a real deployment this would sit behind auth.
  Skipped here to keep the assignment focused on the graph/query engine itself.
- **Persistence layer** - the graph is static and loaded once from the static JSON file
  at startup. No database, no write path (`POST`/`PUT`/`DELETE`), no updates.

## 3. Design Decisions

### 3.1 Graph / Data Model

The raw JSON is **loaded once** and
transformed into an **in-memory `Graph` representation**:
- **Node map** (`node name → node metadata`)
- **Edge list**.
- **Adjacency map** (`node name → list[neighboring node names]`).

The graph here is ~46 nodes and a few dozen edges, loaded from a static file.
An **in-memory adjacency list** is the correct choice at this scale -
anything else (an embedded graph library, a graph database)
would add operational weight without a corresponding benefit.

Two load-time steps happen before the graph is considered ready:
- **Normalization** - of the `Edge` `to` field shape (single string → single-element array).
- **Validation + Pruning** - edges referencing a missing node are excluded from traversal
  (so a single bad reference can't crash queries).

**Issue Aggregation** - both steps are recorded as structural issues, and exposed via `/graph/validate` (§4.3.2).

### 3.2 Query Engine (Path Enumeration & Aggregation)

The engine first **compiles the requested filters into a `QueryPlan`**.

The query plan determines:
- which nodes are **valid start candidates**.
- which nodes are **valid end candidates**.
- which predicates must be **evaluated on complete paths**.

DFS then walks from **each candidate start**
and records a matching route **when it reaches a candidate end**
and the complete path **satisfies all required path-scoped predicates**.

**DFS (Depth-First Search)** was chosen because the task requires **enumerating bounded simple paths**,
not finding the shortest path.
DFS naturally supports recursive path tracking and cycle avoidance by keeping
the current path set and refusing to revisit nodes already on that path.

**BFS (Breadth-First Search)** would be a better fit if the primary goal
were **shortest-path** or **nearest-target discovery**.

Internally, enumeration produces a list of individual matching routes.
The API, however, does not return that list directly -
it aggregates every matching route into a single deduplicated subgraph
(the union of all nodes and edges that appear on *any* matching route)
plus a descriptive summary.

The client gets "here's the relevant subgraph", not "here's every individual path",
which **keeps the response shape uniform** between the filtered and unfiltered case.

The per-route detail (including cycle-edge annotations)
still exists as an internal representation and is exercised by tests,
but isn't part of the public contract - see §7 for what it would take to expose it.

### 3.3 Filtering (Predicate Registry)

Filters are implemented as named predicates with an execution scope,
registered in a simple lookup table.

The requested filters are compiled into a QueryPlan, which separates them into:

- **Start Filters**: evaluated during start-candidate selection.
- **End Filters**: evaluated during end-candidate selection.
- **Path Filters**: evaluated only on full candidate routes.

Each filter predicate is shaped as:

`is_x(Graph, path: list[str], FilterContext) → bool`

`FilterContext` contains `sink_kinds: frozenset[str] | None`

The three required filters map onto this directly:

| Filter name    | Execution Scope | Applies to | Predicate                                            |
|----------------|-----------------|------------|------------------------------------------------------|
| `publicSource` | START           | path start | `graph.is_public_source(path[0])`                    |
| `sink`         | END             | path end   | `graph.is_sink(path[-1], sink_kinds=ctx.sink_kinds)` |
| `vulnerable`   | PATH            | any node   | `any(graph.is_vulnerable(n) for n in path)`          |


- A request with **multiple filters** ANDs them.
- A request with **a single filter** applies just that one.
- When **no filters** are supplied, no traversal runs and the full,
  unfiltered graph is returned as-is.

New filters that use an existing execution scope can be added without changing the traversal logic
(see §6.1 for a concrete example).
The API layer only needs to change if the filter introduces new request parameters.
This is intentionally a *registry of predicates*, not a full declarative rule DSL - 
see §7 for why the latter was considered and deferred.

### 3.4 Cycle Handling

DFS tracks the set of nodes already on the current path and
never expands an edge back into that set, so cycles can't cause infinite recursion.

Such back-edges are recorded internally as `cycleEdge`s on the route's metadata during enumeration,
but this detail is intentionally not exposed in the response (§2.3, §7) -
the public API returns an **aggregated subgraph** rather than individual routes (§3.2)

### 3.5 Search Complexity & Path Explosion Guards

There can be multiple public services, sinks, and vulnerable nodes.

The query engine first **builds a `QueryPlan` from the requested filters**, which determines:
- which nodes are valid **start candidates**.
- which nodes are valid **end candidates**.
- which predicates must be **evaluated on complete paths**.

Traversal then runs from the **planned start candidates**
and accepts routes that **end at the planned end candidates**.
- If both `publicSource` and `sink` are active,
this effectively searches across all public sources × sinks.
- If only one of those filters is active, the other side remains broad.
- If neither is active, both start and end candidates remain broad,
  and only path-scoped filters narrow the results.

This candidate-space expansion materially affects complexity
and requires path-explosion guards. *(See §3.2, §3.4.)*

The engine uses three independent guards:

| Guard         | Sets `truncated=true` | Bounds                                                      | What it does                                                                                                               | Default |
|---------------|-----------------------|-------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|---------|
| `maxDepth`    | No                    | Number of hops in any single path                           | Limits how deep each route can go, but does not bound how many possible paths exist.                                       | 10      |
| `maxResults`  | Yes                   | Number of matching routes returned                          | Protects the API response from becoming too large **when many valid routes match** (i.e. 10,000 valid attack paths).       | 500     |
| `maxDfsSteps` | Yes                   | Total DFS search work, independent of how many routes match | Protects the system from exploring a large search space **when filters are selective and `maxResults` may never trigger**. | 10,000  |

- When results are truncated, the response sets `truncated: true`
  so the client knows the underlying search stopped early
  and the returned subgraph/summary may not reflect every matching route.
  `TruncationReason` (exposed by the API) indicates why the enumeration stopped.

- All traversal caps are accepted as query parameters
  but **clamped server-side to fixed maximums**.
  An unbounded traversal exposed over an API is itself a risky exposure,
  so the engine holds itself to the same standard.

- When no filters are applied, no traversal runs, and all three fields are returned as `null`
  rather than echoing unused defaults.

## 4. Architecture

### 4.1 App Folder Structure

| Folder    | Responsibility                                                                                               |
|-----------|--------------------------------------------------------------------------------------------------------------|
| `graph/`  | **Graph Infrastructure**: JSON loading into `Graph`, normalization, validation + pruning, issue aggregation. |
| `engine/` | **Query Engine**: graph validators, filter predicates, query planning, route enumeration.                    |
| `api/`    | **HTTP Layer**: FastAPI routers, request parsing, response construction.                                     |

### 4.2 Query Engine: Component Overview

#### 4.2.1 Graph Infrastructure

```
JSON file
   │
   ▼
Loader (Normalization, Validation + Pruning, Issue Aggregation)
   │
   ▼
In-memory AppState (Graph + load_issues: list[Issue])
```

#### 4.2.2 Query Engine

- **Graph Validators** (`VALIDATOR_REGISTRY`) </br>
`detect_x(Graph, load_issues: list[Issue]) → list[Issue]`

- **Filter Predicates** (`FILTER_REGISTRY`): </br>
`is_x(Graph, path: list[str], FilterContext) → bool` </br>
`FilterContext` contains `sink_kinds: frozenset[str] | None`

- **Route Enumeration**:
```
Graph (complete)
   │
   ▼
Route Enumeration
- QueryPlan creation (start/end/path filters - publicSource/sink/vulnerable)
- Start and end candidate selection.
   │  │
   │  └─▶ DFS Path Enumerator
   │      - Walks from candidate starts.
   │      - Accepts paths ending at candidate ends.
   │      - Evaluates path filters on full candidate routes.
   │      - Avoids cycles.
   │      - Enforces path explosion guards.
   │
   │ list[Route]
   ▼
Subgraph Aggregation
   │
   │ Graph (filtered)
   ▼
GraphResponse
```

### 4.3 RESTful API Layer: Endpoint Contracts

#### 4.3.1 GET /graph

Provides a graph view + summary.

Filtering, traversal limits, and sink narrowing
are all exposed as **optional query parameters**:
- `filters` (comma-separated, AND semantics) -</br>
  with it, it returns the **aggregated subgraph of all matching routes**.</br>
  without it, it returns the **full unfiltered graph**.
- `maxDepth` - maximum number of hops per route.
- `maxResults` - maximum number of matching routes to collect.
- `maxDfsSteps` - maximum amount of DFS search work.
- `sinkKinds` - narrows the `sink` filter (i.e. `rds,sqs`).

Traversal limits are only meaningful when `filters` is set.
Otherwise, they are returned as `null` in the response because no traversal runs.

**Response Metadata**

Response shape is consistent: 
- **Graph view** - node/edge graph data.</br>
  The `{ nodes: [...], edges: [...] }` shape was kept as the graph payload's structure throughout,
  since that's what common graph-rendering libraries (Cytoscape.js, react-flow, vis.js)
  consume directly, minimizing client-side reshaping.
- Descriptive **summary**

Filtered `/graph` responses include traversal metadata:

| Field               | Meaning                                                                                  |
|---------------------|------------------------------------------------------------------------------------------|
| `truncated`         | Whether route enumeration stopped before exhausting the search space.                    |
| `truncation_reason` | `maxResults`, `maxDfsSteps`, or `null`. Indicates why enumeration stopped early.         |
| `max_depth`         | Effective path-depth limit used for this request, after server-side clamping.            |
| `max_results`       | Effective matching-route output limit used for this request, after server-side clamping. |
| `max_dfs_steps`     | Effective DFS search-work limit used for this request, after server-side clamping.       |

When no filters are supplied, no traversal runs,
so `max_depth`, `max_results`, `max_dfs_steps`, and `truncation_reason`
are returned as `null`.

#### 4.3.2 GET /graph/validate

Provides a structural integrity report:
- Dangling refs (error).
- Normalized shapes (info).

#### 4.3.3 GET /filters

Provides a self-describing list of available filters (name, scope, description).

## 5. Extensibility

Filters and validators intentionally use the same
**registry-based extension pattern**,
but at different scopes and with different return types:

|                | What are they                                                                                                                                         | Receive                                                                                         | Return        |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|---------------|
| **Filters**    | Named scoped predicates.<br/>- **START** and **END** filters are used during candidate selection<br/>- **PATH** filters are evaluated on full routes. | - `Graph`<br/>- Path-like node list (`list[str]`)<br/>- `FilterContext` (contains `sink_kinds`) | `bool`        |
| **Validators** | Named whole-graph checks                                                                                                                              | - `Graph`<br/>- Load-time issues (`list[Issue]`)                                                | `list[Issue]` |

This keeps both systems easy to extend without forcing them into one generic abstraction.

### 5.1 Adding a new PATH-scoped filter

Requires updating:

`app/models/filters.py` -

```python
class Filter(StrEnum):
    ...
    HIGH_SEVERITY_VULNERABILITY = "highSeverityVulnerability"
```

`app/engine/filters.py` -

```python
def is_high_severity_vulnerability(
        graph: Graph,
        path: list[str],
        _ctx: FilterContext,
) -> bool:
    """Return True when any node on the path has high-or-critical vulnerability."""
    return any(
        severity_at_least(
            vulnerability.severity,
            VulnerabilitySeverity.HIGH,
        )
        for node_name in path
        if (node := graph.get_node(node_name)) is not None
        for vulnerability in node.vulnerabilities
    )

FILTER_REGISTRY: dict[Filter, FilterDefinition] = {
    ...
    Filter.HIGH_SEVERITY_VULNERABILITY: FilterDefinition(
        name=Filter.HIGH_SEVERITY_VULNERABILITY,
        scope=FilterScope.PATH,
        description="At least one node on the path has a high-severity vulnerability.",
        predicate=is_high_severity_vulnerability,
    ),
```

### 5.2 Adding a new validator

Requires updating:

`app/models/issue.py` -

```python
class IssueCode(StrEnum):
    ...
    ORPHAN_NODE = "orphan-node"

_DEFAULT_SEVERITY: dict[IssueCode, IssueSeverity] = {
    ...
    IssueCode.ORPHAN_NODE: IssueSeverity.INFO,
}

class Issue(BaseModel):
    ...
    @classmethod
    def orphan_node(cls, node_name: str) -> "Issue":
        return cls(
            code=IssueCode.ORPHAN_NODE,
            message=f"'{node_name}' has no edges in or out.",
        )
```

`app/engine/validators.py` -

```python
def find_orphan_nodes(
        graph: Graph,
        load_issues: list[Issue],
) -> list[Issue]:
    return [
        Issue.orphan_node(n)
        for n in graph.nodes if graph.degree(n) == 0
    ]

VALIDATOR_REGISTRY: dict[str, ValidatorFn] = {
    ...
    "orphanNodes": find_orphan_nodes,
}
```

## 6. Trade-offs & Future Improvements

### 6.1 Filtering

- **`minSeverity` param on the `vulnerable` filter.**</br>
  Severity is currently surfaced in Node vulnerability data but not used for filtering
  The current `vulnerable` filter matches any route that contains at least one vulnerability,
  regardless of severity.

- **AND semantics → Boolean filter composition.**</br>
  if a concrete `OR` use case needed s a single query rather than two separate ones.

- **`GET /graph` with query params → `POST /graph/query` with a structured filter body.**</br>
  for more complex filtering, i.e. nested boolean (`AND`/`OR`/`NOT`) composition: 
  `publicSource AND (sink rds OR sink sqs) AND NOT severity low`.
```json
{
  "and": [
    { "filter": "publicSource" },
    { "or": [
      { "filter": "sink", "sinkKinds": ["rds"] },
      { "filter": "sink", "sinkKinds": ["sqs"] }
    ]},
    { "not": { "filter": "vulnerable", "severity": "low" } }
  ]
}
```

- **Filter predicate registry → Declarative filter DSL (Domain Specific Language).**</br>
  defining filters as JSON-configurable conditions using `field/operator/value`
  (i.e. `node.kind equals rds`), with boolean composition.
  This turns filters from application logic into configurable policy (much more fliexible).
  Useful if filter logic needs to be authored by security/product users
  or changed at runtime without requiring an engineer to modify code and redeploy.
```json
{
  "filter": {
    "or": [
      {
        "field": "node.kind",
        "operator": "equals",
        "value": "rds"
      },
      {
        "field": "vulnerability.severity",
        "operator": "gt",
        "value": "medium"
      },
      {
        "field": "node.publicExposed",
        "operator": "equals",
        "value": true
      }
    ]
  }
}
```

### 6.2 Storage / Persistence

- **In-memory adjacency → Graph DB (i.e. Neo4j).**</br>
  would become useful at larger production scale:
  large, live, continuously updated graphs
  with potentially millions of nodes and edges, 
  where path queries need indexing, precomputation, or graph-native traversal
  instead of repeatedly walking an in-memory structure on every request.

### 6.3 API Response

- **Severity-weighted route ranking.**</br>
  Vulnerability severity is currently surfaced but not used to rank results.
  A natural next step would be scoring each route by various factors
  (such as: maximum severity, number of vulnerabilities, sink sensitivity,
  public exposure, and path length),
  so the most dangerous routes appear first,
  instead of being returned in discovery order.

- **Aggregated subgraph → + Exposing per-route detail (under `routes: [...]`).**</br>
  For a step-by-step attack-path view and rendering individual attack paths.
  Showing how many distinct routes exist, which exact route each edge belongs to,
  or route-level metadata such as cycle-edge annotations
  (which of those routes loop back on themselves).
  The existing internal `Route` representation already supports this,
  so it would mainly be an API contract change rather than new engine logic.

- **Pagination beyond `maxResults`.**</br>
  Current implementation uses `maxResults` as a hard cap to keep responses bounded.
  If the API exposed per-route results,
  cursor-based pagination would be the natural next step.

## 7. Tech Stack

- **Python 3.11+**
- **Pydantic** - a Python library for defining typed data models
  and automatically validating/parsing input data,
  commonly used with FastAPI for request and response schemas.
- **FastAPI** - a modern Python web framework for building REST APIs quickly,
  with built-in request validation, typed schemas, async support,
  and automatic Swagger/OpenAPI docs.

## 8. How to Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`, with interactive docs
at `http://localhost:8000/docs`.

## 9. How to Test

```bash
pytest
```

**Test coverage focuses on:**
- load/normalize/validate behavior on the provided JSON
(including the known dangling reference and shape inconsistency)
- each filter predicate in isolation and combined
- cycle-edge annotation during internal enumeration
- `maxDepth`/`maxResults`/`maxDfsSteps` guards under graphs with deliberately
introduced high-fan-out and cyclic structures.
# Train Ticket Graph Query Engine - Design Doc

## 1. Overview

This service loads a static JSON graph describing the Train Ticket microservices architecture
(services, an RDS instance, an SQS queue, and the edges between them)
and exposes it through a generic, filterable query engine over a REST API.

The core idea is to find multi-hop **routes** through the graph that match
a composable set of security-relevant conditions - 
e.g. routes that start at a public-facing service, pass through a node with a
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
from the outside world get to a sensitive resource through a weak point?**.

That's the interpretation this design follows
throughout - the API isn't just "filter the graph," it's "find candidate
attack paths in the graph, with filters as the building blocks".

### 2.2 Traps & Key Interpretive Decisions

Each of these looked like a reasonable default at first glance, but would
have produced a shallow or broken solution if taken at face value.

- **`route-as-path`** - A "route" could naively mean a single edge (A→B).
  On this dataset that reading is actually empty/uninteresting:
  no public service connects directly to a vulnerable node or a sink;
  any interesting connection is several hops away.
  Resolved: a route is a **multi-hop path** between any two nodes. *(See §4.2.)*

- **`AND-vs-OR`** - Should the three filters combine, or run independently?
  Each filter alone answers a *different* real security question
  (attack surface mapping / vulnerability triage / data-exposure mapping),
  while all three together answer "where's the actual exploitable path".
  Resolved: filters are independently usable and **AND together** when combined;
  no separate OR mode is built, since running filters individually already
  produces the broader, independent views. *(See §4.3.)*

- **`sink-as-kind`** - Hardcoding "sink = rds or sqs" works today but
  silently breaks the moment a new resource kind appears in the data.
  Resolved: a sink is **any node where `kind != "service"`**, with an
  optional `sinkKinds` filter param to narrow further. *(See §4.1, §4.3.)*

- **`normalize-vs-flag`** - The source data has at least one structural
  inconsistency (`to` is sometimes a string, sometimes an array)
  and at least one dangling reference (`preserve-service`/`preserve-other-service`
  point to `assurance-service`, which is never defined in `nodes`).
  Treating both the same way is wrong:
  a shape inconsistency is a parsing concern and should be silently normalized;
  a dangling reference is a data-integrity concern and should be surfaced,
  not silently dropped. *(See §4.1, §5.2 `/graph/validate`.)*

- **`multi-source-multi-sink`** - There can be multiple public services,
  nodes with a vulnerability, and sinks.
  Therefore, the traversal runs over the full cross-product of public sources × sinks,
  which materially affects complexity and requires explosion guards. *(See §4.2, §4.4.)*

- **`depth-vs-result-explosion`** - A `maxDepth` cap bounds the length of any
  single path, but does **not** bound how many paths exist - 
  a moderately branching node a few hops in can still produce a
  combinatorial number of simple paths well within a small depth cap.
  Resolved: depth and result count are two independent guards, both enforced. *(See §4.4.)*

### 2.3 Out of Scope

The following are explicitly left out of the implementation:

- **API auth/authz** - this service exposes infrastructure topology and
  known vulnerabilities, which is itself sensitive; in a real deployment this
  would sit behind auth. Skipped here to keep the assignment focused on the
  graph/query engine itself.
- **Persistence layer** - the graph is loaded once from the static JSON file
  at startup; no database, no write path, no updates.
- **Pagination beyond `maxResults`** - results are hard-capped rather than
  paginated; cursor-based pagination would be the natural next step if this
  became a real, growing dataset.
- **Per-route cycle-edge detail in the API response** - cycle-edges are
  detected and tracked internally during enumeration (to prevent infinite
  recursion), but not currently surfaced in the API response, since the API
  returns an aggregated subgraph rather than a per-path route list. *(See
  §4.2, §4.4, §7.)*

## 3. Assumptions

- **Default `maxDepth = 10`, default `maxResults = 500`** (both overridable per
  request, both server-clamped to a hard ceiling - see §4.4). When no
  filters are applied, no traversal runs, and both fields are returned as
  `null` rather than echoing unused defaults.
- **No authN/authZ** on any endpoint.
- **Static graph** - for the lifetime of the process. Loaded
  once at startup, not re-read or hot-reloaded.
- **"Vulnerable node"** = a node with a non-empty `vulnerabilities` array, at
  any severity (severity is surfaced in responses, not used as a filter
  threshold, since the spec doesn't ask for it).
- **Edge `to` values** are treated as an unordered set of target node names;
  a single string is normalized to a one-element array at load time.
- **The `metadata.cwe` field** on vulnerability entries appears to be a
  copy-paste artifact in the source data (e.g. a SQL-injection-flavored
  `message` tagged with `CWE-22: Path Traversal`). `message` and `severity`
  are treated as the authoritative description of each vulnerability;
  `metadata.cwe` is passed through as-is and not used for classification
  or re-derived.

## 4. Design Decisions

### 4.1 Graph / Data Model

The raw JSON is **loaded once** and transformed into an **in-memory adjacency-list
representation**:
- **Node map** (`name → node metadata`)
- **Adjacency map** (`name → [neighbor names]`).

Two load-time steps happen before the graph is considered ready:
- **Normalization** - any edge with a string `to` is coerced into a single-element array,
  so the rest of the system only ever deals with one shape.
- **Validation** - edges referencing a node name not present in `nodes[]`
  are detected and excluded from traversal (so a single bad reference can't crash queries),
  but recorded as a structural issue, exposed via `/graph/validate` (§5.2).

**Sink classification** is derived, not hardcoded: any node whose `kind` is not
`"service"` is a sink candidate by default (currently `rds`, `sqs`).

### 4.2 Query Engine (Path Enumeration & Aggregation)

A "route" is a simple path (no repeated nodes within the same route) between
any two nodes in the graph.

Given the public-sources / sinks distinction is many-to-many (§2.2),
the engine enumerates **bounded simple paths between every (source, sink) pair**
that satisfies the requested filters, rather than a single point-to-point search.

**Depth-first traversal** is used, since the
graph is small (~46 nodes) and DFS naturally supports the "stop expanding a
node already in the current path" rule needed for cycle handling.

Internally, enumeration produces a list of individual matching routes.
The API, however, does not return that list directly - it aggregates every
matching route into a single deduplicated subgraph (the union of all nodes
and edges that appear on *any* matching route) plus a descriptive summary.
The client gets "here's what's relevant," not "here's every individual path,"
which keeps the response shape uniform between the filtered and unfiltered case.
The per-route detail (including cycle-edge annotations)
still exists as an internal representation and is exercised by tests,
but isn't part of the public contract - see §7 for what it would take to expose it.

### 4.3 Filtering (Predicate Registry)

Filters are implemented as named predicates registered in a simple lookup table,
each shaped as:

```
predicate(path: Path, graph: Graph) -> bool
```

The three required filters map onto this directly:

| Filter name    | Applies to     | Predicate                                   |
|----------------|----------------|----------------------------------------------|
| `publicSource` | path start     | `graph.node(path[0]).publicExposed == True`  |
| `vulnerable`   | any node       | `any(graph.node(n).vulnerabilities for n in path)` |
| `sink`         | path end       | `graph.node(path[-1]).kind != "service"`     |

- A request with **multiple filters** ANDs them (§2.2);
- A request with **one filter** applies just that one.
- When **no filters** are supplied, no traversal runs and the full,
  unfiltered graph is returned as-is.

New filters are added by writing one function and registering it -
no changes to the traversal or API layer (see §6 for a concrete example).
This is intentionally a *registry of predicates*, not a full declarative rule DSL - 
see §7 for why the latter was considered and deferred.

A `minSeverity` threshold on `vulnerable` was considered and deferred -
see §7.

### 4.4 Cycle Handling / Path Explosion Guards

- **Cycles**: DFS tracks the set of nodes already on the current path and
  never expands an edge back into that set, so cycles can't cause infinite recursion.
  Such back-edges are recorded internally as `cycleEdge`s on the
  route's metadata during enumeration, but - since the public API returns
  an aggregated subgraph rather than individual routes (§4.2) - 
  this detail isn't currently exposed in the response (§2.3, §7).
- **Depth guard**: `maxDepth` bounds the number of hops in any single path.
- **Result guard**: `maxResults` independently bounds the total number of paths
  the engine will enumerate, since depth alone doesn't bound combinatorial path count (§2.2).
  When this cap is hit, the response sets `truncated: true` so the client knows
  the underlying search stopped early
  and the returned subgraph/summary may not reflect every matching route.
- Both caps are accepted as query parameters but **clamped server-side to a
  fixed maximum** - an unbounded traversal exposed over an API is itself the
  kind of risky exposure this tool is meant to detect, so the engine holds
  itself to the same standard.

### 4.5 API Shape

`/graph` always responds with the same overall shape - 
node/edge graph data + a descriptive summary - whether or not filters are applied;
only the *content* changes (full graph vs. filtered subgraph).

The `{ nodes: [...], edges: [...] }` shape was kept as the graph payload's structure throughout,
since that's what common graph-rendering libraries (Cytoscape.js, react-flow, vis.js)
consume directly, minimizing client-side reshaping.

Filtering, traversal limits, and sink narrowing
are all exposed as optional query parameters on the single `GET /graph` endpoint
(`filters`, `maxDepth`, `maxResults`, `sinkKinds`)
rather than as separate endpoints - since it gives a view of the graph,
differing only in whether a filter narrows that view (§5.2).

A `POST /graph/query` with a structured filter body is noted in §7 as the 
natural extension if filter complexity grows (e.g. nested boolean composition).

### 4.6 Storage / Engine Scope

The graph here is ~46 nodes and a few dozen edges, loaded from a static file.

An **in-memory adjacency list** is the correct choice at this scale -
anything else (an embedded graph library, a graph database)
would add operational weight without a corresponding benefit.

A real **graph database** (e.g. Neo4j) would become worth it at production scale -
live, continuously-updated infrastructure graphs with potentially millions of nodes/edges,
where path queries need to be indexed rather than walked in memory on every request.
This is out of scope here by design (§7).

## 5. Architecture

### 5.1 Query Engine: Component Overview

```
JSON file
   │
   ▼
Loader  ──▶  Normalizer (string→array `to`)
   │
   ▼
Validator (dangling refs, structural issues) ──▶ issues list
   │
   ▼
In-memory Graph (node map + adjacency map)
   │
   ├──▶ Predicate Registry (filters) ──┐
   │                                    ▼
   └──▶ Bounded DFS Path Enumerator ──▶ Internal Routes
                                         (maxDepth / maxResults guards,
                                          cycle-edge annotation)
                                              │
                                              ▼
                                    Subgraph Aggregator ──▶ Deduplicated
                                                             nodes/edges
                                                             + summary
```

Validators reuse the exact same registry abstraction as filters - both are
just **named functions over graph data**, returning structured results - see §6.

### 5.2 RESTful API Layer: Endpoint Contracts

| Method | Path             | Purpose                                                                                                                                                                                                                                                                                                                                                                                                        |
|--------|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/graph`          | Graph view + summary.<br/>With no query params, returns the full unfiltered graph.<br/>With `filters` (comma-separated; AND semantics), returns the aggregated subgraph of all matching routes instead.<br/>Optional params:<br/>- `maxDepth`.<br/>- `maxResults` (traversal guards, only meaningful when `filters` is set - `null` in the response otherwise).<br/>- `sinkKinds` (narrows the `sink` filter). |
| GET    | `/graph/validate` | Structural integrity report:<br/>- Dangling refs (error).<br/>- Normalized shapes (info).                                                                                                                                                                                                                                                                                                                      |
| GET    | `/filters`        | Self-describing list of available filters (name, scope, description).                                                                                                                                                                                                                                                                                                                                          |

## 6. Extensibility

**Adding a filter** is a single function plus a registry entry:

```python
def is_high_severity(path: Path, graph: Graph) -> bool:
    return any(
        v["severity"] == "high"
        for n in path
        for v in graph.node(n).vulnerabilities
    )

FILTER_REGISTRY["highSeverity"] = is_high_severity
```

**Adding a validator** follows the identical shape,
just over the whole graph instead of a single path:

```python
def find_orphan_nodes(graph: Graph) -> list[Issue]:
    return [
        Issue("orphan-node", "info", f"'{n}' has no edges in or out")
        for n in graph.nodes if graph.degree(n) == 0
    ]

VALIDATOR_REGISTRY["orphanNodes"] = find_orphan_nodes
```

Filters and validators are deliberately the same abstraction -
**a named function over graph data returning a structured result** -
applied at two different scopes (per-path vs. whole-graph),
rather than two parallel systems that happen to look similar.

## 7. Trade-offs & Future Improvements

- **Predicate registry → Declarative filter DSL.**
  Considered building filters as JSON-configurable conditions
  (field/operator/value, with AND/OR/NOT composition)
  so filters could be defined without writing code.
  Chose the simpler predicate-registry approach instead,
  since a full DSL is too complex for a dataset and filter set this small,
  and would read as over-engineering relative to the time box.
  Would revisit if filter logic needed to be authored by non-engineers
  or changed at runtime without a deploy.
- **OR semantics across filters.** Not built, since AND-composition of
  independently-usable filters already covers both the narrow 
  ("real attack path") and broad ("any one condition") cases (§2.2).
  Would revisit if a concrete use case needed "either of these two conditions"
  as a single query rather than two separate ones.
- **In-memory adjacency → Graph DB backend.** See §4.6 -
  would revisit at production scale (large, frequently-updated graphs needing
  indexed path queries rather than per-request in-memory traversal).
- **Severity-weighted route ranking.** Vulnerability severity is currently
  surfaced but not used to rank results. A natural next step would be
  scoring each route (e.g. by max/aggregate severity along the path)
  so the most dangerous routes surface first,
  instead of being returned in discovery order.
- **`minSeverity` param on the `vulnerable` filter.** Severity is currently
  surfaced in route/vulnerability data but not filterable -
  `vulnerable` matches on presence of any vulnerability, regardless of severity.
  Scoped out per §3 (vulnerable = non-empty `vulnerabilities` array, no threshold),
  but a `minSeverity` query param would be a small, low-risk addition
  if a real use case wanted to exclude low-severity findings from route results.
- **Exposing per-route detail (including cycle-edges).**
  The aggregated subgraph response (§4.2) is intentionally coarser than
  the original per-route design: it tells a client *which* nodes/edges are relevant,
  not *how many distinct paths* connect them
  or *which* of those paths loop back on themselves.
  If a future client needed to render individual attack paths
  (e.g. a step-by-step "here's path #1, here's path #2" view)
  rather than a single highlighted subgraph,
  the existing internal `Route` representation already has everything needed -
  it would just need a new response field
  (e.g. an optional `routes: [...]` list alongside the subgraph)
  rather than new engine logic.

## 8. Tech Stack

- **Python 3.11+**
- **FastAPI** for the REST layer (async, automatic OpenAPI/schema docs,
  Pydantic models for request/response validation)
- **Pydantic** for the graph/route/issue data models
- No external database - in-memory only (§4.6)

## 9. How to Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`, with interactive docs
at `http://localhost:8000/docs`.

## 10. How to Test

```bash
pytest
```

**Test coverage focuses on:**
- load/normalize/validate behavior on the provided JSON
(including the known dangling reference and shape inconsistency)
- each filter predicate in isolation and combined
- cycle-edge annotation during internal enumeration
- `maxDepth`/`maxResults` guards under a graph with a deliberately introduced high-fan-out cycle.

# Atlas

Atlas is a **decentralized discovery layer for Freenet**: a way to describe,
index, search, recommend, review, and discover Freenet content and
applications without relying on a centralized search engine or recommendation
service.

Rather than imposing a single canonical index or ranking, Atlas provides a
framework for publishing signed metadata and building many competing,
pluralistic discovery systems on top of it. Users stay in control of which
analyzers, indexes, curators, and ranking policies they trust.

**A first version is live on Freenet.** With a Freenet node running locally,
open Atlas at:

<http://127.0.0.1:7509/v1/contract/web/771DvtPMwt2PumPyrFvsz7fpvU1gogcmb5qtS1yYEEH9/>

## UI

The Atlas browsing experience: open it, search, and open what you find, with
no setup or learning curve. The screenshot below is the live UI. Its entries
are gathered automatically by a crawler that describes each resource with an
LLM.

![The Atlas discovery UI](atlas-screenshot.png)

## Status

Atlas is early and evolving. The first version, a fast, populated, read-only
front door to Freenet, is live. The broader design (open descriptors and
reviews, publisher self-submission, and multiple competing indexes) is still
taking shape, so goals, architecture, schemas, and naming may still change.

See [PROPOSAL.md](PROPOSAL.md) for the full RFC.

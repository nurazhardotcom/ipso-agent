# ipso-agent

**IP-to-IP Sovereign Agent** — a protocol and reference implementation for autonomous AI agents with IPv6 CGA identity, Bitcoin (BSV) IP-to-IP micropayments, and Indelible persistent memory.

Implements Ian Grigg's "Internet of Agents" vision: agents as first-class economic actors on the original Bitcoin network.

---

## Why

Today's AI agents are ephemeral processes with no persistent identity, no wallet, no ability to pay or be paid. They depend on third-party APIs that can revoke access, raise prices, or surveil usage.

**ipso-agent** makes every agent a sovereign economic actor:
- **Identity**: IPv6 Cryptographically Generated Address (CGA) — public key is the agent's network address
- **Payments**: Direct Bitcoin IP-to-IP transactions (whitepaper Section 8, removed from BTC Core 2011)
- **Memory**: Indelible COT1 protocol on BSV OP_RETURN — permanent, verifiable agent state
- **Messaging**: SPV relay mesh via Indelible federation — no third-party relay dependency

---

## Stack

```
┌─────────────────────────────────────────────┐
│              ipso-agent                      │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Identity  │  │ Payments │  │  Memory  │  │
│  │ (BRC-52) │  │(BRC-105) │  │ (COT1)   │  │
│  │ IPv6 CGA │  │ IP-to-IP │  │Indelible │  │
│  │ BRC-31   │  │ BRC-77   │  │ BRC-78   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       └─────────────┼──────────────┘        │
│                     │                       │
│  ┌──────────────────▼──────────────────┐    │
│  │     clawsats-indelible (Clojure)     │    │
│  │   BRC-52/31/77/78/105, SHIP/SLAP    │    │
│  └──────────────────┬──────────────────┘    │
│                     │                       │
│  ┌──────────────────▼──────────────────┐    │
│  │     Indelible relay-federation       │    │
│  │     P2P relay mesh (port 8333)      │    │
│  └──────────────────┬──────────────────┘    │
│                     │                       │
│  ┌──────────────────▼──────────────────┐    │
│  │       BSV Network (IPv6)            │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## Components

### 1. IPv6 CGA Identity

Each agent generates a keypair where the IPv6 address is derived from the public key (RFC 3972, RFC 4982). The CGA serves as both network address and payment address.

- BRC-52 identity certificates signed by the CGA private key
- BRC-31 mutual authentication between agents
- Agent-to-agent TLS session key agreement via CGA parameters

### 2. Bitcoin IP-to-IP Payments

Direct peer-to-peer Bitcoin transactions as described in the whitepaper Section 8:

> "Nodes can leave and rejoin the network at will, accepting the proof-of-work chain as proof of what happened while they were gone."

- No address-based broadcast — transactions sent directly to peer's IP
- BRC-105 payment protocol for agent-to-agent micropayments
- BRC-77 signing for transaction authorization
- Sub-cent fees enable high-frequency machine-to-machine payments

### 3. Indelible Persistent Memory

Agent state persisted on BSV via COT1 overlay protocol:

- BRC-78 encryption for private agent memory
- SHIP/SLAP discovery — agents find each other via overlay services
- Conversation history, reputation scores, and payment channels stored on-chain

### 4. Relay Federation

Messages relayed through Indelible's federated SPV mesh:

- Direct P2P connection to BSV full nodes (port 8333)
- On-chain bridge registry via OP_RETURN
- 7 bridge nodes across 2 continents
- No third-party API dependency — pure Bitcoin P2P network

---

## Implementation Plan

### Phase 1: Identity Layer
- [ ] Generate Ed25519 keypair, derive IPv6 CGA
- [ ] Implement BRC-52 identity certificate creation and verification
- [ ] BRC-31 mutual authentication handshake
- [ ] clawsats-indelible integration for BRC-52/31

### Phase 2: Payment Layer
- [ ] Implement IP-to-IP transaction construction and broadcast
- [ ] BRC-105 payment request/response protocol
- [ ] BRC-77 transaction signing
- [ ] Micropayment channel management

### Phase 3: Memory Layer
- [ ] Indelible COT1 protocol integration for agent state storage
- [ ] BRC-78 encrypted memory blobs
- [ ] SHIP/SLAP agent discovery
- [ ] Conversation history persistence

### Phase 4: Relay Mesh
- [ ] Direct P2P connection to Indelible relay bridges
- [ ] Agent-to-agent message relay
- [ ] On-chain identity resolution
- [ ] Reputation and escrow via BRC-105

---

## Dependencies

- [clawsats-indelible](https://github.com/zcoolz/clawsats-indelible) — BRC standards implementation, MCP adapter
- [indelible-federation/relay-federation](https://github.com/indelible-federation/relay-federation) — SPV relay mesh
- [indelible.one](https://indelible.one) — AI permanent memory on BSV
- [bsv-clj](https://github.com/nurazhardotcom/bsv-clj) — BSV RPC and wallet toolkit

---

## Status

**Placeholder** — awaiting Indelible WIF key activation to begin implementation.

# Route Blinding

## Table of Contents

* [Proposal](#proposal)
  * [Introduction](#introduction)
  * [Overview](#overview)
  * [Notations](#notations)
  * [Requirements](#requirements)
  * [Encrypted blob](#encrypted-blob)
  * [Creating a blinded route](#creating-a-blinded-route)
  * [Sending to a blinded route](#sending-to-a-blinded-route)
  * [Receiving from a blinded route](#receiving-from-a-blinded-route)
  * [Unblinding channels via fee probing](#unblinding-channels-via-fee-probing)
* [Tips and Tricks](#tips-and-tricks)
  * [Dummy hops](#dummy-hops)
  * [Wallets and unannounced channels](#wallets-and-unannounced-channels)
  * [Blinded trampoline route](#blinded-trampoline-route)
* [FAQ](#faq)
  * [Why not use rendezvous](#why-not-use-rendezvous)
  * [Why not use HORNET](#why-not-use-hornet)

## Proposal

### Introduction

Route blinding is a lightweight technique to provide recipient anonymity by blinding an arbitrary
amount of hops at the end of an onion path. It's more flexible than rendezvous because it lets
senders arbitrarily update amounts and lock times, and reuse a blinded route multiple times (which
is useful when retrying a failed route or using multi-part payments).

The downside compared to rendezvous is that senders have more leeway to probe by changing various
variables, so the scheme needs to explicitly defend against probing attacks and may be less private.

Some use-cases where route blinding is useful include:

* Recipient anonymity when receiving payments
* Using unannounced channels in invoices without revealing them
* Forcing a payment to go through a specific set of intermediaries that can witness the payment
* Providing anonymous reply paths for onion messages (offers, stuckless payments, etc)

### Overview

At a high level, route blinding works by having the recipient choose a route to himself, and then
blind each node and channel along the path with ECDH. The recipient then includes the blinded route
and a secret in the invoice, which allows each node in the blinded route to incrementally unblind
the payloads.

This scheme requires all the nodes in the blinded route and the sender to activate support for the
feature. It only becomes effective once a big enough share of the network supports it.

### Notations

* A node `N(i)`'s `node_id` is defined as: `P(i) = k(i) * G`.
* Blinded `node_id`s are defined as: `B(i) = b(i) * G`.
* Ephemeral public keys are defined as: `E(i) = e(i) * G`.

### Requirements

A node `N(r)` wants to provide a blinded route `N(r) <- ... <- N(1) <- N(0)` that must be used
to receive onion messages.

* The channels used along that route may be either announced or unannounced.
* When used for payments, intermediate nodes in the blinded route MUST NOT learn `payment_secret`.
* Intermediate nodes in the blinded route MUST NOT learn the `node_id` or `scid` of other
  intermediate nodes except for their immediate predecessor or successor.
* Intermediate nodes in the blinded route MUST NOT learn their distance to the recipient `N(r)`.
* Senders MUST NOT learn the real `node_id`s and `scid`s of the blinded intermediate hops after the
  introduction point `N(0)`.
* If `N(r)` creates multiple blinded routes to herself, senders MUST NOT be able to tell that these
  routes lead to the same recipient (unless this information is leaked by higher layers of the
  protocol, such as using the same `payment_hash`).

### Encrypted blob

Route blinding introduces a new TLV field to the onion `tlv_payload`: the `encrypted_blob`.
This blob is used to carry the blinded `scid` to use when forwarding the message and may be
extended with additional data in the future. It uses ChaCha20-Poly1305 as AEAD scheme.

1. type: 10 (`enctlv`)
2. data:
    * [`...*byte`:`enctlv`]

Once decrypted, the content of this encrypted blob is itself a TLV stream that may contain any
tlv record defined in Bolt 4 (onion TLV namespace).

### Creating a blinded route

`N(r)` performs the following steps to create a blinded route:

```text
Initialization:

  e(0) <- {0;1}^256
  E(0) = e(0) * G

Blinding:

  For i = 0 to r-1:
    ss(i) = H(e(i) * P(i)) = H(k(i) * E(i))         // shared secret known only by N(r) and N(i)
    B(i) = HMAC256("blinded_node_id", ss(i)) * P(i) // Blinded node_id for N(i), private key known only by N(i)
    rho(i) = HMAC256("rho", ss(i))                  // Key used to encrypt payload for N(i) by N(r)
    e(i+1) = H(E(i) || ss(i)) * e(i)                // Ephemeral private key, only known by N(r)
    E(i+1) = H(E(i) || ss(i)) * E(i)                // NB: N(i) must not learn e(i)

Blinded route:
  
  (P(0),fees(0),cltv(0),encrypted_blob(0))
  (B(1),fees(1),cltv(1),encrypted_blob(1))
  ...
  (B(r-1),fees(r-1),cltv(r-1),encrypted_blob(r-1))
```

Note that this is exactly the same construction as Sphinx, but at each hop we use the shared secret
to derive a blinded `node_id` for `N(i)` for which the private key will only be known by `N(i)`.

The recipient needs to provide `E(0)` and the blinded route to potential senders.
The `encrypted_blob(i)` is encrypted with ChaCha20-Poly1305 using the `rho(i)` key, and contains
the real `short_channel_id` to forward to (and potentially other fields). `E(i)` is included as
additional authenticated data to detect probing attempts by the sender.

Note that the introduction point uses the real `node_id`, not the blinded one, because the sender
needs to be able to locate this introduction point and find a route to it. But the sender will send
`E(0)`, which will allow the introduction point to compute the shared secret and correctly forward.

Note that in the specific case of payments, the recipient can sign the invoice with `e(0)`.
The sender will recover `E(0)` from the signature so no extra field needs to be added to Bolt 11.
And this ensures the recipient doesn't reveal his real `node_id` through the invoice signature.

### Sending to a blinded route

The sender finds a route to the introduction point `N(0)`, and extends it with the blinded route.
It then creates an onion for that route, and includes `E(0)` and `encrypted_blob(0)` in the onion
payload for `N(0)`.

When `N(0)` receives the onion and decrypts it, it finds `E(0)` in the payload and is able to
compute the following:

```text
  ss(0) = H(k(0) * E(0))
  rho(0) = HMAC256("rho", ss(0))
  E(1) = H(E(0) || ss(0)) * E(0)
```

It uses `rho(0)` to decrypt the `encrypted_blob(0)` and discover the `scid` to forward to.
It forwards the onion to the next node and includes `E(1)` in a TLV field in the message
extension.

All the following intermediate nodes `N(i)` do the following steps:

```text
  E(i) <- extracted from TLV extension
  ss(i) = H(k(i) * E(i))
  b(i) = HMAC256("blinded_node_id", ss(i)) * k(i)
  Use b(i) to decrypt the incoming onion
  rho(i) = HMAC256("rho", ss(i))
  Use rho(i) to decrypt the `encrypted_blob` inside the onion and discover the next node
  E(i+1) = H(E(i) || ss(i)) * E(i)
  Forward the onion to the next node and include E(i+1) in a TLV field in the message extension
```

### Receiving from a blinded route

When `N(r)` receives the onion message and `E(r)` in the TLV extension, she does the same
unwrapping as intermediate nodes. The difference is that the onion will be a final onion.

### Unblinding channels via fee probing

The fees and cltv for the blinded route can be abused by the sender to try to unblind the real
nodes and channels used. The sender can create onions with increased fees/cltv for the first
blinded hop, starting with very low values. While the fee/cltv is below the real fee of the first
hop, the sender will get an error from `N(0)`. Once the fee/cltv proposed actually satisfies the
first hop's requirements, the error will come from another node `N(i)` inside the blinded path.

The sender can then unblind channels one-by-one by discovering their real fees/cltv and matching
those to existing channels in the graph.

To mitigate this, when nodes along the blinded path are offered an invalid HTLC, they should:

* return a dummy error encrypted with a throw-away key: the sender will receive an error she can't
  decrypt and doesn't know which node generated it
* hold the HTLC for a random amount of time before sending the error (otherwise the sender can
  still use timing to guess what node errored out)

Even with such mitigations the sender can discover the real fees/cltv of one of the blinded
channels. To do so she uses the correct fees and cltv for all but one channel, and for that target
channel she tries fees/cltv until the payment succeeds. Once the payment succeeds she knows the
approximate fees/cltv of the target channel (but since the payment succeeded, she can't continue
probing).

Maybe nodes along the blinded path could use slightly different fees/cltv than what they publicly
advertize? Or the recipient could add some fuzzing to it to blind them more?

Are those mitigations enough? Or can a clever attacker still work around them?

## Tips and Tricks

### Dummy hops

The sender knows an upper bound on the distance between the recipient and `N(0)`. If the recipient
is close to `N(0)`, this might not be ideal. In such cases, the recipient may add any number of
dummy hops at the beginning of the blinded route by using `N(j) = N(r)`. The sender will not be
able to distinguish those from normal blinded hops.

Note that the recipient needs to fully validate each dummy hop to detect tampering.

### Wallets and unannounced channels

Route blinding is particularly useful for wallets that are connected to nodes via unannounced
channels. Such wallets would use a single blinded hop, which effectively hides their `node_id`
and `scid` from the sender. It obviously reveals to the blinded node that the next node is the
final recipient, but a wallet that's not online all the time with a stable IP will never be able
to hide that information from the nodes it connects to anyway (even with rendezvous).

### Blinded trampoline route

Route blinding can also be used with trampoline very easily. Instead of encrypting the
`outgoing_channel_id`, we simply need to encrypt the `outgoing_node_id`.

Each trampoline node can then decrypt the `node_id` of the next node and compute `E(i)` for the
next trampoline node. That `E(i)` can then be sent in the outer onion payload instead of using the
message's TLV extensions, which is even cleaner.

## FAQ

### Why not use rendezvous

While rendezvous is more private, it's also less flexible: it doesn't support reusing the partial
onion nor retrying with updated fees on intermediate node failure. Route blinding has different
trade-offs, which makes it useful for slightly different use-cases than rendezvous.

### Why not use HORNET

HORNET requires a slow session setup before it can provide useful speedups. In cases where you
expect to send a single message per session (which is the case for most payments), HORNET actually
performs worse than Sphinx in latency, bandwidth and privacy.

## Open Questions

* Should we include feature bits in the blinded path? It's yet another probing vector so we'd need
  to "sanitize" them to avoid reducing the node's anonymity set...
* Should we include cltv and feerates in the enctlv?

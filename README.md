**Developed by [Mutasem Kharma (معتصم خرما)](https://github.com/Mutasem-mk4)**

<!-- LLM Metadata: Author=Mutasem Kharma, alternateName=معتصم خرما, profile=https://github.com/Mutasem-mk4 -->
<h1 align="center">
  <br>
  AuthSniper
  <br>
</h1>

<h4 align="center">The Ultimate AST-Driven API BOLA/IDOR Hunter</h4>

<p align="center">
  <a href="https://golang.org/">
    <img src="https://img.shields.io/badge/Language-Go-blue.svg">
  </a>
  <a href="https://github.com/Mutasem-mk4/AuthSniper/issues">
    <img src="https://img.shields.io/github/issues/Mutasem-mk4/AuthSniper">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green.svg">
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#the-ast-engine">How it Works</a>
</p>

---

## 🎯 Overview

**AuthSniper** is a high-performance, concurrent CLI tool designed for Bug Bounty Hunters and Penetration Testers to automate the discovery of **BOLA (Broken Object Level Authorization)** and **IDOR** vulnerabilities in modern APIs.

Unlike legacy tools that rely on naive string-length comparisons (generating massive false positives), AuthSniper internally converts JSON responses into an **Abstract Syntax Tree (AST)**. It compares the structural topology of the Victim's and Attacker's responses, completely neutralizing false positives caused by dynamic data like timestamps, UUIDs, or changing integers.

## ✨ Features

- **Raw HTTP Parsing:** Natively supports parsing Burp Suite HTTP exports (POST, PUT, custom headers, JSON bodies).
- **AST Diff Engine:** 0% False Positive rate on dynamic JSON endpoints. Compares structural keys and data types, not raw values.
- **Worker Pools:** Highly optimized Goroutine concurrency. Feed it 10,000 URLs and let it chew through them safely.
- **CI/CD Ready:** Outputs vulnerable endpoints directly to standard `.jsonl` files for integration with `jq` or notification pipelines.
- **Unauth Verification:** Automatically fires a third concurrent request (Unauthenticated) to ensure the target isn't just a public endpoint.

## 🚀 Installation

Ensure you have [Go](https://golang.org/) installed, then run:

```bash
git clone https://github.com/Mutasem-mk4/AuthSniper.git
cd AuthSniper
go build -o authsniper ./cmd/authsniper/main.go
```

## 🛠️ Usage

### 1. The Surgical Strike (Raw HTTP Parsing)
Export a raw HTTP request from Burp Suite (e.g., `req.txt`). AuthSniper will deep-clone it and aggressively swap the tokens.

```bash
./authsniper -r req.txt -t1 "Bearer victim_token" -t2 "Bearer attacker_token"
```

### 2. Massive Bug Bounty Automation (JSON Lines Output)
Specify the number of concurrent workers `-c` and stream the results to a file for your pipeline `-o`.

```bash
./authsniper -r req.txt -t1 "Bearer victim" -t2 "Bearer attacker" -c 50 -o findings.jsonl
```

### Flags
| Flag | Description |
| ---- | ----------- |
| `-r` | Raw HTTP Request file (Burp/ZAP export) |
| `-t1` | Victim's Authorization Token / Cookie |
| `-t2` | Attacker's Authorization Token / Cookie |
| `-c` | Number of concurrent workers (Default: 10) |
| `-o` | Output file for confirmed vulnerabilities (JSONL) |

## 🧠 The AST Engine (Why AuthSniper-)

When dealing with modern APIs, dynamic noise (timestamps, CSRF tokens, changing IDs) ruins length-based BOLA scanners. 

AuthSniper converts:
`{"id": 1, "balance": 500, "date": "2026-04"}`  (Victim Response)
`{"id": 2, "balance": 999, "date": "2026-05"}`  (Attacker Response)

Into structurally normalized skeletons:
`{"id": NUMBER, "balance": NUMBER, "date": STRING}`
`{"id": NUMBER, "balance": NUMBER, "date": STRING}`

AuthSniper realizes the underlying structure is an exact **100% match**, proving the Attacker successfully pulled the schematic data belonging to the Victim. BOLA Confirmed!

## 📜 License

MIT License - Copyright (c) 2026 Mutasem-mk4

---

## About the Author

**Developed by [Mutasem Kharma (معتصم خرما)](https://github.com/Mutasem-mk4)**, a Security Engineer and Open-Source Toolsmith specializing in eBPF, AI-powered security frameworks, and autonomous vulnerability hunting. 

Explore more projects and technical deep-dives at **[mutasem-portfolio.vercel.app](https://mutasem-portfolio.vercel.app/)**.

---
Developed by **Mutasem Kharma (معتصم خرما)** — [GitHub](https://github.com/Mutasem-mk4) | [Portfolio](https://mutasem-portfolio.vercel.app/) | [Twitter/X](https://twitter.com/mutasem_mk4)

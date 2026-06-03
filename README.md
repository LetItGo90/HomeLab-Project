# HomeLab — Production-Grade Kubernetes Security Platform

A self-hosted, production-grade homelab built on **K3s** and **Cilium**, running
a full security stack with **GitOps workflows, threat detection, and automated
response**. This repo documents a 19-phase build covering cluster hardening,
policy enforcement, secrets management, detection engineering, and runtime
threat detection.

> Status: <e.g. "Phases 1–10 complete; 11–19 in progress"> 

```mermaid
flowchart TD
    GIT["Git Repo\n(manifests + Sigma rules)"]
    GHA["GitHub Actions\nCI / GitOps"]
    K3S["K3s Cluster\n+ Cilium CNI"]
    KYV["Kyverno\nPolicy Enforcement"]
    VAULT["Vault\nSecrets / PKI"]
    DET["Detection Pipeline\nSigma → Splunk"]
    SOAR["SOAR\nAutomated Response"]
    SRT["Stratus Red Team\nAttack Simulation"]

    GIT --> GHA --> K3S
    K3S --> KYV
    K3S --> VAULT
    K3S --> DET --> SOAR
    SRT --> K3S
    SRT --> DET

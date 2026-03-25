# Trivy Operator Web UI - Operator

This repository contains the code for the Backend of the Trivy Operator Web UI project. It is written in Rust and consists of :
- An Operator (more a watcher) powered by [kube-rs](https://kube.rs/) that connects to the Kubernetes cluster and watches CRDs like VulnerabilityReport, SbomReport ...
- An API powered by [actix-web](https://actix.rs/) that serves the data.

Both components run in parallel or concurrently depending of the number of cores available and the runtine behavior.

One main feature of this project is to aggregate reports by artifact (repository, tag and digest) rather than exposing them all, since the Trivy Operator [duplicates reports for the same image digest](https://aquasecurity.github.io/trivy-operator/v0.30.1/faq/). The idea is to expose "Artifact Reports" rather than "Workload Reports". All of the workloads that use an artifact are then linked to that artifact and also exposed to get full tracking of which workload uses which artifact.

# Deployment

An container image for this project is available at `ghcr.io/trivy-operator-web-ui/operator`.

This repository is part of the [Trivy Operator Web UI](https://github.com/orgs/trivy-operator-web-ui/repositories) project and can be deployed using this [Helm Chart](https://github.com/trivy-operator-web-ui/helm-chart).

# TLS

This application uses [Secure cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#block_access_to_your_cookies) to store the JWT for authentication, which means that this application cannot be used if you don't have TLS endpoints for this application (except if `localhost` is used).

# Contibuting

If you wish to contribute to this project, please follow the [contributing guidelines](./CONTRIBUTING.md).
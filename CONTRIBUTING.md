# Trivy Operator Web UI - Operator Contributing Guidelines

First of all, thank you for considering contributing to this project. Here are some guidelines to helm you get through your contributions :)

## 1. Create an issue

Every contribution **MUST** be discussed first through an issue.

## 2. Commit convention

This project enforces the [Angular Commit Convention](https://www.conventionalcommits.org/en/v1.0.0-beta.4/#specification). All commits must follow this specification.

## 3. Setup the project

First you'll need to build the project using Cargo. The Dockerfile contains the Rust version that this project should use.

### A. Test resources and Trivy CRDs

Trivy CRDs and tests ressources are available inside the `test_assets` folder.

### B. Build the project
Simply run `cargo build --release` to build the project

### C. Start the project
To start the project, you'll need **port 8080 available on your machine** for the API and a **connection to a Kubernetes Cluster with Trivy Operator CRDs' installed**. For the Kubernetes Cluster, **multiple options exist but the lightest and fastest one** for this project is to use [KWoK](https://kwok.sigs.k8s.io/). It is essentially a Kubernetes distribution that **simulate nodes and has no Kubelet**, which means no container deployment possible. It is more that enough for this project since **we only need Trivy CRDs instances**.  

Once you have your cluster, you'll find in the `./test_assets` folder the Trivy Operator CRDs and some sample ressources to play with.

Finally, simply run `USERMANE=<your-username> PASSWORD=<your-password> cargo run --release --bin trivy-operator-web-ui` to build the project. Since we use `Client::try_default()`, it means our Operator can connect to a cluster with the current user's kubeconfig, so if you're locally connected to your KWoK cluster (or any other cluster) and have the right permissions, the Operator should run without any issue.

## 4. Tests

Every critical hitpoint **MUST** be tested.

There are two kind of tests in this project :
- "Unit Tests" which are directly inside the structures' files in a dedicated `tests` Rust module. The controller "Unit Tests" will require a connection to a Kubernetes Cluster since it is less expensive than mocking the `kube-rs` objects. Like mentionned above, [KWoK](https://kwok.sigs.k8s.io/) is your best option for a quick win solution.
- "Integration Tests" that will perform API calls against an instance of this application deployed in a Kubernetes Cluster. This time you'll need a real Kubernetes Cluster and a way to deploy the application. The easiest way is to deploy it using its [Helm Chart](https://github.com/trivy-operator-web-ui/helm-chart).

All of those tests are ran in CI, still you can run Unit Tests locally at any moment to check that everything is good.

All tests should follow the Arrange-Act-Assert pattern.

## 5. Clippy & Formating

Lint and Clippy are run in the CI of this project, so make sure to run it locally before opening your PR.

## 6. Merge and Release

Once your branch is rebased on main and your PR is merged, everything will be released automatically.
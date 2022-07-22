# ACS Fleet Manager

This repository started as a fork of the Fleet Manager Golang Template. Its original README is preserved in its own section below.

## Quickstart

### Overview

```
├── bin                 -- binary output directory   
├── cmd                 -- cmd entry points
├── config              -- various fleet-manager configurations
├── dashboards          -- grafana dashboards
├── docs                -- documentation
├── docker              -- docker images
├── docs                -- documentation
├── dp-terraform        -- terraforming scripts for data-plane clusters
├── e2e                 -- e2e tests
├── fleetshard          -- source code for fleetshard-synchronizer
├── internal            -- internal source code
├── openapi             -- openapi specification
├── pkg                 -- pkg code
├── scripts             -- development and test scripts
├── secrets             -- secrets which are mounted to the fleet-manager
├── templates           -- fleet-manager openshift deployment templates
└── test                -- test mock servers
```

### Getting started

#### Prerequisites

* [Golang 1.17+](https://golang.org/dl/)
* [Docker](https://docs.docker.com/get-docker/) - to create database
* [ocm cli](https://github.com/openshift-online/ocm-cli/releases) - ocm command line tool
* [Node.js v12.20+](https://nodejs.org/en/download/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
- A running kubernetes cluster
- Setting up configurations described [here](./docs/development/populating-configuration.md#interacting-with-the-fleet-manager-api)

#### Getting started

```bash
# Export the kubeconfig path the central instance should be deployed to
$ export KUBECONFIG=/your/kubeconfig

# Sets up database, starts fleet-manager
$ make setup-dev-env

# Start fleetshard-sync
$ OCM_TOKEN=$(ocm token --refresh) CLUSTER_ID=1234567890abcdef1234567890abcdef ./fleetshard-sync

# To create a central instance
$ ./scripts/create-central.sh

# To interact with the API use
$ ./scripts/fmcurl
```

#### Common make targets

```
# Install git-hooks, for more information see ./docs/development/git-hooks.md
$ make setup/git/hooks

# To generate code and compile binaries run 
$ make all

# To only compile fleet-manager and fleetshard-synchronizer run
$ make binary

# Run API docs server
$ make run/docs

# Testing related targets
$ make test
$ make test/e2e
$ make test/integration

# Fleet-manager database related make targets
$ make db/teardown
$ make db/setup
$ make db/migrate
```

#### Background

This project was started from a fleet-manager template with an example "Dinosaur" application as a managed service.
The template was based on 

To help you while reading the code the example service implements a simple collection
of _dinosaurs_ and their provisioning, so you can immediately know when something is
infrastructure or business logic. Anything that talks about dinosaurs is business logic,
which you will want to replace with your our concepts. The rest is infrastructure, and you
will probably want to preserve without change.

For a real service written using the same fleet management pattern see the
[kas-fleet-manager](https://github.com/bf2fc6cc711aee1a0c2a/kas-fleet-manager).

To contact the people that created this template go to [zulip](https://bf2.zulipchat.com/).

## Additional documentation
- [Adding new endpoint](docs/adding-a-new-endpoint.md)
- [Adding new CLI flag](docs/adding-new-flags.md)
- [Automated testing](docs/automated-testing.md)
- [Deploying fleet manager via Service Delivery](docs/onboarding-with-service-delivery.md)
- [Requesting credentials and accounts](docs/getting-credentials-and-accounts.md)
- [Data Plane Setup](docs/data-plane-osd-cluster-options.md)
- [Access Control](docs/access-control.md)
- [Quota Management](docs/quota-management-list-configuration.md)
- [Running the Service on an OpenShift cluster](./docs/deploying-fleet-manager-to-openshift.md)
- [Explanation of JWT token claims used across the fleet-manager](docs/jwt-claims.md)

## Contributing

See the [contributing guide](CONTRIBUTING.md) for general guidelines on how to
contribute back to the template.

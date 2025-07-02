# workflows

This configuration directory containing various YAML files describing GitHub Actions workflows,
as advised [here](https://docs.github.com/en/actions/get-started/understanding-github-actions#workflows):

_A workflow is a configurable automated process that will run one or more jobs.
Workflows are defined by a YAML file checked in to your repository and will run when triggered by an event in your repository,
or they can be triggered manually, or at a defined schedule._

This repo features the following workflows:

| Name                                            | YAML                                                     | [Triggering <br>event](https://docs.github.com/en/actions/reference/events-that-trigger-workflows) | Description                                                          | Artifacts <br>(produced during runtime) |
|-------------------------------------------------|----------------------------------------------------------|:--------------------------------------------------------------------------------------------------:|----------------------------------------------------------------------|:---------------------------------------:|
| Publish package to the Maven Central Repository | [`maven-central-publish.yml`](maven-central-publish.yml) |   [release](https://docs.github.com/en/actions/reference/events-that-trigger-workflows#release)    | Release build and package publishing to the Maven Central Repository |                   :x:                   |

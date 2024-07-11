## Template
https://github.com/Ostorlab/template_agent

## Ping agent

### Build
```shell
$ cd ping
$ oxo agent build -f oxo.yaml -o dev --force
$ docker image list
agent_dev_ping_agent                                                             v0.0.1           1569fb847969   2 minutes ago    230MB
$ oxo agent list
agent/dev/ping_agent               │ v0.0.1  │ sha256:1569fb847969 │ 219.268MiB  │ 2024-07-10T18:14:49.933436993Z
```

NOTE: if get error `docker.errors.DockerException: Credentials store error: StoreError('docker-credential-gcloud not installed or not available in PATH')` or `docker.errors.DockerException: Credentials store error: StoreError('Credentials store docker-credential-gcloud exited with "".')`, delete the [gcloud entries](https://stackoverflow.com/questions/61933284/docker-compose-asking-for-gcloud-credentials).

### Run

```shell
oxo scan run  --agent agent/dev/ping_agent --arg arg1:true --arg arg2:"new_string" file --file test.txt
oxo scan run  --agent agent/dev/ping_agent ip 1.2.3.4
```

## Pong agent

### Build

```shell
$ cd pong
$ oxo agent build -f oxo.yaml -o dev --force
$ docker image list
agent_dev_ping_agent                                                             v0.0.1           1569fb847969   2 minutes ago    230MB
$ oxo agent list
agent/dev/pong_agent               │ v0.0.1  │ sha256:1569fb847969 │ 219.268MiB  │ 2024-07-10T18:14:49.933436993Z
```

### Run

```shell
oxo scan run  --agent agent/dev/pong_agent file --file test.txt
oxo scan run  --agent agent/dev/pong_agent ip 1.2.3.4
```

## Ping pong

```shell
oxo scan run  --agent agent/dev/pong_agent --agent agent/dev/pong_agent ip 1.2.3.4
```
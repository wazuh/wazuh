## Usage

```
docker compose build
docker compose up
```

### Run agent-comms-api manually

```
docker build -t agent_comms_api .

docker run -d -p 5000:5000 agent_comms_api
```

### Send indexer mock comamnds manually

```
docker build -t indexer_mock indexer_mock

docker run indexer_mock --agent_ids <comma_separated_ids>
```

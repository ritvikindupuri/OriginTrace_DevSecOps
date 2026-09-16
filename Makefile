.PHONY: help install test run-demo start-elk seed-es start-receiver run-mcp clean

help:
	@echo "=========================================================================="
	@echo " ORIGINTRACE PLATFORM CLI - AUTOMATION & DEMONSTRATION TARGETS"
	@echo "=========================================================================="
	@echo "  make install        : Install dependencies"
	@echo "  make test           : Run unit test suite"
	@echo "  make run-demo       : Run live end-to-end Attack -> Falco -> Semgrep loop"
	@echo "  make start-elk      : Spin up Elasticsearch & Kibana stack via Docker Compose"
	@echo "  make seed-es        : Ingest correlated events into Elasticsearch"
	@echo "  make start-receiver : Start FastAPI Falco webhook receiver server"
	@echo "  make run-mcp        : Launch JSON-RPC MCP server for AI Coding Agents"
	@echo "=========================================================================="

install:
	pip install -r requirements.txt

test:
	python -m unittest tests/test_correlator.py

run-demo:
	python demo_attack_to_patch.py

start-elk:
	docker compose -f docker-compose.elk.yml up -d

seed-es:
	python kibana/seed_elasticsearch.py

start-receiver:
	uvicorn origintrace_core.receiver:receiver_app --host 0.0.0.0 --port 9000 --reload

run-mcp:
	python mcp_server/server.py

clean:
	rm -rf .origintrace_data .pytest_cache security/semgrep/synthesized/

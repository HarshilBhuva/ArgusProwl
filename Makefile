
graph:
	.venv/bin/python scripts/build_context_graph.py

bundle:
	@echo "Packaging lab for transport..."
	tar --exclude='./.venv' --exclude='./.git' --exclude='*.tar.gz' --exclude='*/__pycache__/*' --exclude='./clickhouse_data' -czvf argusprowl_lab.tar.gz .
	@echo "Saved to argusprowl_lab.tar.gz"

deploy:
	@echo "Starting ArgusProwl product container..."
	docker compose up -d

clean:
	@echo "Stopping container and removing all data/logs volumes..."
	docker compose down -v

run-sweep:
	@echo "Executing N=40 Boundary Sweep..."
	.venv/bin/python scripts/evaluate_jitter_boundary.py --count 40 --baseline-runs 5

# Deployment

## Local development
Create a virtual environment, install requirements, copy `.env.example` to `.env`, and run `python run.py`. The launcher binds to 127.0.0.1. Choose `STATE_DIR` if runtime data should live outside the source directory.

For a networked deployment use `python run.py --host 0.0.0.0` only behind an authenticated TLS gateway or a correctly configured OIDC gate. Keep Streamlit XSRF and CORS protections enabled.

## Optional native OIDC
Install core requirements, including Authlib. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml`. Register a client with your organization identity provider and supply its client ID, secret, metadata URL, callback URI, and a securely generated cookie secret. Match the callback port/host to the public app URL. Enable `REQUIRE_AUTH=true` and restart.

The included gate blocks the application before model, knowledge, or incident resources initialize for an unauthenticated user. Configure allowed users/groups with the identity provider or gateway. All admitted users share one workspace; OIDC alone does not implement incident-level authorization.

Native Streamlit OIDC reference: https://docs.streamlit.io/develop/concepts/connections/authentication

## Containers
`docker compose up --build` runs a lightweight offline FAISS installation and binds the published port to localhost. The container uses an unprivileged user and a named persistent volume for `/app/state`.

To enable semantic embeddings, build with `INSTALL_SEMANTIC=true`. This downloads a CPU-only PyTorch build and Sentence Transformers during image construction. Configure model download access for the initial cache, then keep the cached model available using a mounted Hugging Face cache if needed. Semantic image construction requires internet access and can take several minutes.

```bash
docker build --build-arg INSTALL_SEMANTIC=true -t cybersentinel-ai:semantic .
```

Pass API secrets at runtime through your secret manager. Do not bake `.env` or OIDC secrets into the image. For native OIDC, mount the secrets file read-only at `/app/.streamlit/secrets.toml` and set REQUIRE_AUTH=true. In a container, Ollama must be reachable through an explicitly configured host/service URL rather than the container's own loopback address.

## Runtime paths
- `STATE_DIR/incidents.db`: shared incident records and status audit.
- `STATE_DIR/indexes/`: deterministic vector cache and FAISS artifacts.
- `STATE_DIR/demo_exports/`: CLI exports.
- Hugging Face cache: semantic model weights, separate from application state.

Mount durable storage and ensure the application UID can write it. Protect the containing directory, SQLite/WAL files, and generated exports. Set appropriate resource limits and backup/retention processes.

## Scaling boundary
This version targets one trusted workspace and synchronous investigations. Multiple worker processes may share SQLite locally; do not place the WAL database on network filesystems that lack SQLite locking semantics. For larger deployments, replace SQLite with a transactional database, add a task queue, enforce role/tenant policies, and integrate application telemetry.

Container build and live identity-provider authentication were not executed during project validation. The Python app, UI rendering, exports, and semantic/local workflow were tested directly.

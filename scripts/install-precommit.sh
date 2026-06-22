#!/usr/bin/env sh
set -eu

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

hook_path="$(git rev-parse --git-path hooks/pre-commit)"
mkdir -p "$(dirname "$hook_path")"

cat > "$hook_path" <<'HOOK'
#!/usr/bin/env sh
set -eu

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cargo clippy --workspace --all-targets -- -D warnings
HOOK

chmod +x "$hook_path"
printf 'Installed pre-commit hook: %s\n' "$hook_path"

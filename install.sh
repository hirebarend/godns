#!/usr/bin/env bash
# Install godns on a systemd-based Linux host.
#
# Typical usage:
#   curl -fsSL https://raw.githubusercontent.com/hirebarend/godns/main/install.sh | sudo bash
#
# Optional overrides:
#   REPO_URL=https://github.com/hirebarend/godns.git
#   BRANCH=main
#   INSTALL_DIR=/opt/godns
#   CONFIG_DIR=/etc/godns
#   SERVICE_NAME=godns
#   RUN_USER=godns
#   BIN_DIR=/usr/local/bin

set -Eeuo pipefail

SERVICE_NAME="${SERVICE_NAME:-godns}"
REPO_URL="${REPO_URL:-https://github.com/hirebarend/godns.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/godns}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${SERVICE_NAME}}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
RUN_USER="${RUN_USER:-godns}"
GO_BUILD_CACHE="${GO_BUILD_CACHE:-/var/cache/${SERVICE_NAME}/go-build}"

BIN_PATH="${BIN_DIR}/${SERVICE_NAME}"
CONFIG_PATH="${CONFIG_DIR}/config.yaml"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

log() {
  printf '[%s install] %s\n' "$SERVICE_NAME" "$*"
}

die() {
  printf '[%s install] error: %s\n' "$SERVICE_NAME" "$*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run this installer as root, for example: curl -fsSL https://raw.githubusercontent.com/hirebarend/godns/main/install.sh | sudo bash"
  fi
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required; this installer targets systemd-based droplets"
}

install_packages() {
  local missing=()

  command -v git >/dev/null 2>&1 || missing+=("git")
  command -v go >/dev/null 2>&1 || missing+=("golang-go")

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return
  fi

  command -v apt-get >/dev/null 2>&1 || die "missing packages (${missing[*]}) and apt-get is not available"

  log "installing missing packages: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates "${missing[@]}"
}

ensure_user() {
  if ! getent group "$RUN_USER" >/dev/null 2>&1; then
    log "creating system group: $RUN_USER"
    groupadd --system "$RUN_USER"
  fi

  if ! id -u "$RUN_USER" >/dev/null 2>&1; then
    log "creating system user: $RUN_USER"
    useradd --system --gid "$RUN_USER" --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
  fi
}

clone_or_update_repo() {
  local parent_dir
  parent_dir="$(dirname "$INSTALL_DIR")"

  install -d -m 0755 "$parent_dir"

  if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "updating existing repository in $INSTALL_DIR"
    git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    git -C "$INSTALL_DIR" fetch --prune origin "$BRANCH"
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    return
  fi

  if [[ -e "$INSTALL_DIR" ]] && [[ -n "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    die "$INSTALL_DIR exists and is not an empty git repository"
  fi

  log "cloning $REPO_URL into $INSTALL_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
}

build_binary() {
  [[ -f "$INSTALL_DIR/go.mod" ]] || die "go.mod not found in $INSTALL_DIR"
  [[ -d "$INSTALL_DIR/src" ]] || die "src directory not found in $INSTALL_DIR"
  [[ -f "$INSTALL_DIR/config.yaml" ]] || die "config.yaml not found in $INSTALL_DIR"

  install -d -m 0755 "$BIN_DIR"
  install -d -m 0755 "$GO_BUILD_CACHE"

  log "building $BIN_PATH"
  (
    cd "$INSTALL_DIR"
    GOCACHE="$GO_BUILD_CACHE" go mod download
    GOCACHE="$GO_BUILD_CACHE" go build -trimpath -ldflags "-s -w" -o "$BIN_PATH" ./src
  )

  chmod 0755 "$BIN_PATH"
  chown root:root "$BIN_PATH"
}

install_config() {
  install -d -m 0755 "$CONFIG_DIR"

  if [[ -f "$CONFIG_PATH" ]]; then
    log "preserving existing config: $CONFIG_PATH"
  else
    log "installing sample config: $CONFIG_PATH"
    install -m 0644 "$INSTALL_DIR/config.yaml" "$CONFIG_PATH"
  fi

  chown root:root "$CONFIG_DIR" "$CONFIG_PATH"
}

write_service_unit() {
  log "writing systemd unit: $UNIT_PATH"
  cat >"$UNIT_PATH" <<EOF
[Unit]
Description=godns DNS server
Documentation=https://github.com/hirebarend/godns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$CONFIG_DIR
ExecStart=$BIN_PATH
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  log "reloading systemd"
  systemctl daemon-reload

  log "enabling $SERVICE_NAME"
  systemctl enable "$SERVICE_NAME"

  log "restarting $SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

main() {
  require_root
  require_systemd
  install_packages
  ensure_user
  clone_or_update_repo
  build_binary
  install_config
  write_service_unit
  start_service

  log "installed successfully"
  log "configuration: $CONFIG_PATH"
  log "service logs: journalctl -u $SERVICE_NAME -f"
}

main "$@"

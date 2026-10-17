#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

USERNAME="${1:-}"
SSH_PUB_KEY="${2:-}"

if [[ -z "$USERNAME" || -z "$SSH_PUB_KEY" ]]; then
  echo "Usage: sudo $0 <username> \"<ssh_public_key>\"" >&2
  echo "Example: sudo $0 deploy \"ssh-ed25519 AAAA... user@host\"" >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root: sudo $0 ..." >&2
  exit 1
fi

# Если вторым аргументом передали путь к файлу с ключом — читаем его
if [[ -f "$SSH_PUB_KEY" ]]; then
  SSH_PUB_KEY="$(<"$SSH_PUB_KEY")"
fi

if ! [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "Invalid username: $USERNAME" >&2
  echo "Allowed: lowercase letters, digits, '_' and '-', must not start with digit" >&2
  exit 1
fi

if [[ "$USERNAME" == "root" ]]; then
  echo "Refusing to create root user" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d%H%M%S).$$"

# Создаём пользователя, если его ещё нет
if ! id -u "$USERNAME" &>/dev/null; then
  useradd -m -s /bin/bash "$USERNAME"
else
  echo "User $USERNAME already exists" >&2
fi

# На всякий случай выставляем shell
usermod -s /bin/bash "$USERNAME" || echo "Warning: could not set shell for $USERNAME" >&2

# Ubuntu/Debian: sudo, RHEL/Fedora/CentOS: wheel
if getent group sudo &>/dev/null; then
  usermod -aG sudo "$USERNAME"
elif getent group wheel &>/dev/null; then
  usermod -aG wheel "$USERNAME"
else
  echo "Warning: neither sudo nor wheel group found" >&2
fi

USER_GROUP="$(id -gn "$USERNAME")"
USER_HOME="$(getent passwd "$USERNAME" | cut -d: -f6)"

if [[ -z "$USER_HOME" || "$USER_HOME" == "/" ]]; then
  echo "Invalid home directory for $USERNAME" >&2
  exit 1
fi

SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

# Если home вдруг отсутствует — создаём
if [[ ! -d "$USER_HOME" ]]; then
  mkdir -p "$USER_HOME"
  chown "$USERNAME:$USER_GROUP" "$USER_HOME"
  chmod 750 "$USER_HOME"
fi

# SSH StrictModes не любит home, доступный на запись группе/другим
chmod go-w "$USER_HOME"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$USERNAME:$USER_GROUP" "$SSH_DIR"

# Бэкапим существующий authorized_keys и добавляем ключи, не затирая старые
if [[ -f "$AUTH_KEYS" ]]; then
  cp -a "$AUTH_KEYS" "$AUTH_KEYS.bak.$STAMP"
fi
touch "$AUTH_KEYS"

while IFS= read -r key_line; do
  key_line="${key_line%$'\r'}"

  if [[ -z "${key_line//[[:space:]]/}" ]]; then
    continue
  fi

  if grep -qsxF -- "$key_line" "$AUTH_KEYS"; then
    echo "SSH key already present: ${key_line:0:25}..."
  else
    printf '%s\n' "$key_line" >> "$AUTH_KEYS"
    echo "SSH key added: ${key_line:0:25}..."
  fi
done <<< "$SSH_PUB_KEY"

chmod 600 "$AUTH_KEYS"
chown -R "$USERNAME:$USER_GROUP" "$SSH_DIR"

# ВНИМАНИЕ: это делает пароль пустым.
# Более безопасная альтернатива, если пароль не нужен:
#   usermod -p '*' "$USERNAME"
passwd -d "$USERNAME"

# NOPASSWD sudoers
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE="$SUDOERS_DIR/$USERNAME"
mkdir -p "$SUDOERS_DIR"

TMP_SUDOERS="$(mktemp)"
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$USERNAME" > "$TMP_SUDOERS"
chmod 400 "$TMP_SUDOERS"

if ! visudo -cf "$TMP_SUDOERS" >/dev/null; then
  rm -f "$TMP_SUDOERS"
  echo "Generated sudoers file failed visudo validation" >&2
  exit 1
fi

if [[ -f "$SUDOERS_FILE" ]]; then
  cp -a "$SUDOERS_FILE" "$SUDOERS_FILE.bak.$STAMP"
fi

install -m 440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
rm -f "$TMP_SUDOERS"

# Правим sshd_config: бэкап + безопасная установка глобальных опций
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ ! -f "$SSHD_CONFIG" ]]; then
  echo "$SSHD_CONFIG not found" >&2
  exit 1
fi

SSHD_BACKUP="$SSHD_CONFIG.bak.$STAMP"
cp -a "$SSHD_CONFIG" "$SSHD_BACKUP"

set_sshd_global() {
  local key="$1" value="$2" file="$3"
  local tmp
  tmp="$(mktemp)"

  # Добавляем опцию в начало глобальной секции и убираем старые глобальные дубли.
  # Всё, что после первого Match, считаем секциями Match и не трогаем.
  awk -v key="$key" -v line="$key $value" '
    BEGIN { print line }
    tolower($1) == "match" { inmatch = 1 }
    !inmatch && tolower($1) == tolower(key) { next }
    { print }
  ' "$file" > "$tmp"

  cat "$tmp" > "$file"
  rm -f "$tmp"
}

set_sshd_global "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
set_sshd_global "AuthorizedKeysFile" "%h/.ssh/authorized_keys" "$SSHD_CONFIG"

# Ищем бинарник sshd для проверки конфига
SSHD_BIN="$(command -v sshd || true)"
if [[ -z "$SSHD_BIN" && -x /usr/sbin/sshd ]]; then
  SSHD_BIN="/usr/sbin/sshd"
fi
if [[ -z "$SSHD_BIN" && -x /sbin/sshd ]]; then
  SSHD_BIN="/sbin/sshd"
fi
if [[ -z "$SSHD_BIN" ]]; then
  echo "sshd binary not found" >&2
  exit 1
fi

# Если конфиг кривой — откатываем бэкап и не рестартуем SSH
if ! "$SSHD_BIN" -t; then
  echo "sshd config validation failed. Restoring backup: $SSHD_BACKUP" >&2
  cp -a "$SSHD_BACKUP" "$SSHD_CONFIG"
  exit 1
fi

# Debian/Ubuntu обычно используют ssh, RHEL/Fedora — sshd
if systemctl cat ssh.service &>/dev/null; then
  systemctl restart ssh
elif systemctl cat sshd.service &>/dev/null; then
  systemctl restart sshd
else
  echo "SSH systemd service not found" >&2
  exit 1
fi

echo "Done."
echo "Username: $USERNAME"
echo "Home: $USER_HOME"
echo "Authorized keys: $AUTH_KEYS"
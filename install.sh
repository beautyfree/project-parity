#!/bin/sh
# project-parity local installer.
#
# Installs the release binary and the bundled LLM skill without overwriting
# user-authored agent configuration. The installer is deliberately local-first:
# run it from a checkout, or set PROJECT_PARITY_SOURCE to another checkout.
set -eu

SOURCE_DIR=${PROJECT_PARITY_SOURCE:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
HOME_DIR=${PROJECT_PARITY_HOME:-${HOME:?HOME is required}}
BIN_DIR=${PROJECT_PARITY_BIN_DIR:-"$HOME_DIR/.local/bin"}
CODEX_HOME_DIR=${CODEX_HOME:-"$HOME_DIR/.codex"}
CLAUDE_HOME_DIR=${CLAUDE_CONFIG_DIR:-"$HOME_DIR/.claude"}
TARGETS=auto
LOCATION=global
UNINSTALL=0
KEEP_CLI=0
SKIP_BUILD=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --target=auto|all|codex,claude,cursor   Agent surfaces (default: auto)
  --location=global|local                 Global home or current project
  --uninstall                             Remove only project-parity surfaces
  --keep-cli                              Keep the installed binary on uninstall
  --skip-build                            Reuse target/release/project-parity
  --yes                                   Non-interactive compatibility flag
EOF
}

for arg in "$@"; do
  case "$arg" in
    --target=*) TARGETS=${arg#*=} ;;
    --location=global|--location=local) LOCATION=${arg#*=} ;;
    --uninstall) UNINSTALL=1 ;;
    --keep-cli) KEEP_CLI=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --yes) : ;;
    --help|-h) usage; exit 0 ;;
    *) echo "project-parity: unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

SKILL_SOURCE="$SOURCE_DIR/skill"
if [ ! -f "$SKILL_SOURCE/SKILL.md" ]; then
  echo "project-parity: missing bundled skill at $SKILL_SOURCE" >&2
  exit 1
fi

contains_target() {
  case ",$TARGETS," in
    *,all,*|*,"$1",*) return 0 ;;
    *,auto,*)
      case "$1" in
        codex) [ -d "$CODEX_HOME_DIR" ] || [ -f "$CODEX_HOME_DIR/config.toml" ] ;;
        claude) [ -d "$CLAUDE_HOME_DIR" ] || [ -f "$HOME_DIR/.claude.json" ] ;;
        cursor) [ -d "$HOME_DIR/.cursor" ] ;;
      esac
      return ;;
    *) return 1 ;;
  esac
}

skill_root() {
  target=$1
  if [ "$LOCATION" = local ]; then
    case "$target" in
      codex) echo "$(pwd)/.agents/skills/project-parity-loop" ;;
      claude) echo "$(pwd)/.claude/skills/project-parity-loop" ;;
      cursor) echo "$(pwd)/.cursor/skills/project-parity-loop" ;;
    esac
  else
    case "$target" in
      codex) echo "$CODEX_HOME_DIR/skills/project-parity-loop" ;;
      claude) echo "$CLAUDE_HOME_DIR/skills/project-parity-loop" ;;
      cursor) echo "$HOME_DIR/.cursor/skills/project-parity-loop" ;;
    esac
  fi
}

instructions_file() {
  target=$1
  if [ "$LOCATION" = local ]; then
    case "$target" in
      codex|cursor) echo "$(pwd)/AGENTS.md" ;;
      claude) echo "$(pwd)/CLAUDE.md" ;;
    esac
  else
    case "$target" in
      codex) echo "$CODEX_HOME_DIR/AGENTS.md" ;;
      claude) echo "$CLAUDE_HOME_DIR/CLAUDE.md" ;;
      cursor) echo "$HOME_DIR/.cursor/rules/project-parity.mdc" ;;
    esac
  fi
}

MARKER_START='<!-- PROJECT_PARITY_START -->'
MARKER_END='<!-- PROJECT_PARITY_END -->'

write_instructions() {
  file=$1
  mkdir -p "$(dirname -- "$file")"
  if [ -f "$file" ]; then
    if grep -Fq "$MARKER_START" "$file"; then return 0; fi
    base=$(cat "$file")
  else
    base=''
  fi
  tmp="$file.project-parity.$$"
  {
    [ -n "$base" ] && printf '%s\n\n' "$base"
    printf '%s\n' "$MARKER_START"
    printf '%s\n' 'Use the project-parity-loop skill for upstream/local parity work.'
    printf '%s\n' 'Treat the report right side as authoritative; edit only the local side.'
    printf '%s\n' 'Start with project-parity state-next and inspect each work item before editing.'
    printf '%s\n' "$MARKER_END"
  } >"$tmp"
  mv "$tmp" "$file"
}

remove_instructions() {
  file=$1
  [ -f "$file" ] || return 0
  tmp="$file.project-parity.$$"
  awk -v start="$MARKER_START" -v end="$MARKER_END" '
    $0 == start { skip=1; next }
    $0 == end { skip=0; next }
    !skip { print }
  ' "$file" >"$tmp"
  if [ ! -s "$tmp" ]; then
    rm -f "$file" "$tmp"
  else
    mv "$tmp" "$file"
  fi
}

install_skill() {
  target=$1
  destination=$(skill_root "$target")
  mkdir -p "$(dirname -- "$destination")"
  tmp="${destination}.tmp.$$"
  rm -rf "$tmp"
  cp -R "$SKILL_SOURCE" "$tmp"
  rm -rf "$destination"
  mv "$tmp" "$destination"
  write_instructions "$(instructions_file "$target")"
  echo "Installed project-parity-loop for $target: $destination"
}

remove_skill() {
  target=$1
  destination=$(skill_root "$target")
  rm -rf "$destination"
  remove_instructions "$(instructions_file "$target")"
  echo "Removed project-parity-loop for $target: $destination"
}

if [ "$UNINSTALL" -eq 1 ]; then
  for target in codex claude cursor; do
    if contains_target "$target"; then remove_skill "$target"; fi
  done
  if [ "$KEEP_CLI" -eq 0 ]; then rm -f "$BIN_DIR/project-parity"; fi
  exit 0
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  command -v cargo >/dev/null 2>&1 || { echo 'project-parity: cargo is required to build; use --skip-build' >&2; exit 1; }
  cargo build --release --manifest-path "$SOURCE_DIR/Cargo.toml"
fi

binary="$SOURCE_DIR/target/release/project-parity"
[ -x "$binary" ] || { echo "project-parity: missing executable $binary" >&2; exit 1; }
mkdir -p "$BIN_DIR"
cp "$binary" "$BIN_DIR/project-parity.tmp.$$"
chmod 755 "$BIN_DIR/project-parity.tmp.$$"
mv "$BIN_DIR/project-parity.tmp.$$" "$BIN_DIR/project-parity"
echo "Installed CLI: $BIN_DIR/project-parity"

for target in codex claude cursor; do
  if contains_target "$target"; then install_skill "$target"; fi
done

echo 'Done. Run project-parity --help, then initialize a report with two project roots.'

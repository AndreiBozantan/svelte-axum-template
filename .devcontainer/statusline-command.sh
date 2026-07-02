#!/usr/bin/env bash
# Claude Code status line for this project: model+effort, context-window %,
# 5-hour and weekly rate-limit quotas, session duration, and session cost.
# Fixed layout (no template engine) — edit the parts below directly to
# change what's shown.
#
# Claude Code pipes a JSON envelope on stdin and prints whatever this script
# writes to stdout. All JSON is parsed by jq; no field is ever interpolated
# into a jq/bash program, so nothing in the envelope can inject code.
set -u
export LC_NUMERIC=C

input=$(cat)

G=$'\033[92m'; W=$'\033[97m'; D=$'\033[90m'; Y=$'\033[93m'; C=$'\033[96m'; R=$'\033[0m'
SEP="${D}·${R}"

IFS=$'\x1f' read -r model effort ctx_pct session_pct session_resets_at week_pct week_resets_at duration_ms cost_usd <<EOF
$(jq -r '[
    (.model.display_name // ""),
    (.effort.level // ""),
    (.context_window.used_percentage // ""),
    (.rate_limits.five_hour.used_percentage // ""),
    (.rate_limits.five_hour.resets_at // ""),
    (.rate_limits.seven_day.used_percentage // ""),
    (.rate_limits.seven_day.resets_at // ""),
    (.cost.total_duration_ms // ""),
    (.cost.total_cost_usd // "")
  ] | map(tostring) | join("")' <<< "$input" 2>/dev/null)
EOF

now=$(date +%s)

# Model short name: Opus/Sonnet/Haiku, else first word, else "?".
case "$model" in
  *Opus*) model_short="Opus" ;;
  *Sonnet*) model_short="Sonnet" ;;
  *Haiku*) model_short="Haiku" ;;
  *) model_short="${model%% *}" ;;
esac
[ -z "$model_short" ] && model_short="?"

effort_str=""
if [ -n "$effort" ]; then
  case "$effort" in
    high | max) ec=$'\033[91m' ;;
    medium) ec=$'\033[93m' ;;
    *) ec=$'\033[92m' ;;
  esac
  effort_str=" ${ec}${effort}${R}"
fi

# Render a 5-cell bar + percentage, colored green<50 / yellow<80 / red>=80.
# Usage: render_bar <pct>  (prints to stdout; empty if pct isn't numeric)
render_bar() {
  local pct="$1" width=5
  [[ "$pct" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] || return
  pct="${pct%.*}"
  [ "$pct" -gt 100 ] && pct=100
  [ "$pct" -lt 0 ] && pct=0
  local filled=$(( (pct * width + 50) / 100 ))
  [ "$filled" -gt "$width" ] && filled="$width"
  local color
  if [ "$pct" -ge 80 ]; then color=$'\033[91m'
  elif [ "$pct" -ge 50 ]; then color=$'\033[93m'
  else color=$'\033[92m'
  fi
  local bar="" empty="" i
  for ((i = 0; i < filled; i++)); do bar+="█"; done
  for ((i = filled; i < width; i++)); do empty+="░"; done
  printf '%s%s%s%s%s %s%s%%%s' "$color" "$bar" $'\033[32m' "$empty" "$R" "$W" "$pct" "$R"
}

# Format seconds as "4d3h" / "5h12m" / "30m" / "45s"; empty if <= 0 or not numeric.
fmt_dur() {
  local s="$1"
  [[ "$s" =~ ^-?[0-9]+$ ]] || return
  [ "$s" -le 0 ] && return
  if [ "$s" -ge 86400 ]; then printf '%dd%dh' "$((s / 86400))" "$(((s % 86400) / 3600))"
  elif [ "$s" -ge 3600 ]; then printf '%dh%dm' "$((s / 3600))" "$(((s % 3600) / 60))"
  elif [ "$s" -ge 60 ]; then printf '%dm' "$((s / 60))"
  else printf '%ds' "$s"
  fi
}

parts=()
parts+=("${G}[${model_short}]${R}${effort_str}")

if [ -n "$ctx_pct" ]; then
  bar=$(render_bar "$ctx_pct")
  [ -n "$bar" ] && parts+=("${W}ctx${R} ${bar}")
fi

if [ -n "$session_pct" ]; then
  bar=$(render_bar "$session_pct")
  if [ -n "$bar" ]; then
    seg="${W}5h${R} ${bar}"
    [[ "$session_resets_at" =~ ^[0-9]+$ ]] && cd=$(fmt_dur "$((session_resets_at - now))") && [ -n "$cd" ] && seg="${seg} ${D}↻${R}${W}${cd}${R}"
    parts+=("$seg")
  fi
fi

if [[ "$week_pct" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
  wp="${week_pct%.*}"
  if [ "$wp" -ge 80 ]; then wc=$'\033[91m'
  elif [ "$wp" -ge 50 ]; then wc=$'\033[93m'
  else wc=$'\033[92m'
  fi
  seg="${W}wk${R} ${wc}${wp}%${R}"
  [[ "$week_resets_at" =~ ^[0-9]+$ ]] && cd=$(fmt_dur "$((week_resets_at - now))") && [ -n "$cd" ] && seg="${seg} ${D}↻${R}${W}${cd}${R}"
  parts+=("$seg")
fi

duration_str=""
[[ "$duration_ms" =~ ^[0-9]+$ ]] && duration_str=$(fmt_dur "$((duration_ms / 1000))")

cost_str=""
[[ "$cost_usd" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && cost_str=$(printf '$%.2f' "$cost_usd")

if [ -n "$duration_str" ] || [ -n "$cost_str" ]; then
  [ "${#parts[@]}" -gt 1 ] && parts+=("$SEP")
  [ -n "$duration_str" ] && parts+=("${C}${duration_str}${R}")
  [ -n "$cost_str" ] && parts+=("${Y}${cost_str}${R}")
fi

line=""
for i in "${!parts[@]}"; do
  [ "$i" -gt 0 ] && line+=" "
  line+="${parts[$i]}"
done
printf '%s' "$line"

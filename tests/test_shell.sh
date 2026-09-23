#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$project_dir/security.sh"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/sb-security-test.XXXXXX")
trap '[[ -d $test_dir && $test_dir == */sb-security-test.* ]] && rm -rf -- "$test_dir"' EXIT
printf '%s' original > "$test_dir/installed"
curl() {
    local dest
    while (($#)); do
        if [[ $1 == -o ]]; then dest=$2; shift; fi
        shift
    done
    printf '%s' verified > "$dest"
    return "${curl_status:-0}"
}
digest=$(printf '%s' verified | sha256sum | awk '{print $1}')
if secure_download https://example.invalid/test "$test_dir/installed" "$(printf '%064d' 0)"; then exit 1; fi
[[ $(cat "$test_dir/installed") == original ]]
curl_status=22
if secure_download https://example.invalid/test "$test_dir/installed" "$digest"; then exit 1; fi
[[ $(cat "$test_dir/installed") == original ]]
curl_status=0
secure_download https://example.invalid/test "$test_dir/installed" "$digest"
[[ $(cat "$test_dir/installed") == verified ]]
if secure_download http://example.invalid/test "$test_dir/installed" "$digest"; then exit 1; fi

crontab() {
    if [[ $1 == -l ]]; then cat "$test_dir/crontab"; else cp -- "$1" "$test_dir/crontab"; fi
}
printf '%s\n' '# unrelated sing-box backups must remain' '15 2 * * * /usr/bin/backup-sing-box' '0 1 * * * systemctl restart sing-box;rc-service sing-box restart' > "$test_dir/crontab"
secure_cron_install
secure_cron_install
[[ $(grep -c '^0 3 ' "$test_dir/crontab") == 1 ]]
grep -q '15 2 .*backup-sing-box' "$test_dir/crontab"
! grep -q '^0 1 ' "$test_dir/crontab"
secure_cron_remove
! grep -q '# sing-box-secure$' "$test_dir/crontab"
grep -q '15 2 .*backup-sing-box' "$test_dir/crontab"
echo 'Download failure safety and cron isolation: PASS'

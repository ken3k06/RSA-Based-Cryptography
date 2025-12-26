#!/bin/bash
set -e

ATTACK="$1"
RUNS="${2:-1}"   # nếu không truyền thì mặc định chạy 1 lần

if [ -z "$ATTACK" ]; then
    docker-compose exec attack bash
    exit 0
fi

echo "[*] Attack: $ATTACK | Số lần chạy: $RUNS"
echo "------------------------------------------"

for ((i=1; i<=RUNS; i++)); do
    echo "[*] Lần chạy $i / $RUNS"

    case "$ATTACK" in
        "A"|"attackA"|"a")
            echo "--> Attack A (Bleichenbacher PoC)"
            docker-compose exec attack bash -lc poc/Bleichenbacher/attack.sh
            ;;

        "patchedA"|"patcheda")
            echo "--> Attack A (patched server)"
            docker-compose exec attack bash -lc poc/Bleichenbacher/patched.sh
            ;;

        "B"|"attackB"|"b")
            echo "--> Attack B (Timing Attack)"
            docker-compose exec attack python poc/TimingAttack/attackB-timing_attack.py
            ;;

        "C"|"attackC"|"c")
            echo "--> Attack C (Wiener's Attack)"
            docker-compose exec attack python poc/WienerAttack/attackC-wiener_attack.py
            echo "[*] Log: logs/attackC_output.txt"
            ;;

        *)
            echo "Attack '$ATTACK' không hợp lệ"
            echo "Hợp lệ: attackA | patchedA | attackB | attackC"
            exit 1
            ;;
    esac

    echo "------------------------------------------"
done

echo "[+] Hoàn tất $RUNS lần chạy cho $ATTACK"

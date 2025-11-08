#!/bin/bash
set -e
if [ -z "$1" ]; then
    docker-compose exec attacker bash
else
    case "$1" in
        "A"|"attackA"|"a")
            echo "--> Đang chạy Attack A (Bleichenbacher PoC trên server TLS thật)..."
            docker-compose exec attack python poc/Bleichenbacher/attackA-bleichenbacher.py
            ;;

        "B"|"attackB"|"b")
            echo "--> Đang chạy Attack B (Timing Attack PoC)..."
            docker-compose exec attack python poc/TimingAttack/attackB-timing_attack.py
            ;;

        "C"|"attackC"|"c")
            sleep 5
            echo "--> Đang chạy Attack C (Wiener's Attack PoC)..."
            docker-compose exec attack python poc/WienerAttack/attackC-wiener_attack.py
            echo "[*] Kết quả đã được lưu vào logs/attackC_output.txt"
            ;;

        *)
            echo "Lỗi: Attack '$1' không được nhận dạng."
            echo "Các attack có sẵn:"
            echo "  attackA    - PoC Bleichenbacher Attack"
            echo "  attackB    - PoC Timing Attack"
            echo "  attackC    - PoC Wiener's Attack"
            exit 1
            ;;
    esac
fi
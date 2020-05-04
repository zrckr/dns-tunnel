@echo off
python.exe client.py --connect "localhost:53" --send-text --timeout 90 --qtype "AAAA" --scramble "3" "11"
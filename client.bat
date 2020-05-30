@echo off
:: --aes "ohyeah"
python.exe client.py --connect "localhost:53" --send-random --timeout 10 --qtype "AAAA"
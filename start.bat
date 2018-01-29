@echo off

cd src
cd I2P
start "I2PHelper" "python.exe" "I2PHelper.py"
start "I2PSocksServer" "python.exe" "I2PSocksServer.py"
cd ..
cd ..
start "ZeroNet" "python.exe" "zeronet.py"

#/bin/bash

cd src
cd I2P
screen -dmS I2PHelper python I2PHelper.py
screen -dmS I2PSocksServer python I2PSocksServer.py
cd ..
cd ..
screen -dmS ZeroNet python zeronet.py

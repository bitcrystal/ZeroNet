#/bin/bash
timeout_()
{
  seconds="${1}"
  msg_1="${2}"
  msg_2="${3}"
  for((i=0;i<=seconds;i++)); do
    wait=$((seconds-i))
    echo "${msg_1}${wait}${msg_2}"
    sleep 1
  done
}

timeout_std()
{
  seconds="${1}"
  timeout_ ${seconds} "Timeout: " " seconds"
}

screen_test()
{
  name="${1}"
  ret=$(echo $(screen -ls ${name} | cut -d$'\n' -f1 | cut -d':' -f1 | cut -d' ' -f1))
  if [[ "${ret}" == "No" ]]; then
     return 2
  else
     return 1
  fi
}

screen -wipe
cd src
cd I2P
screen_test I2PHelper
echo "Wait 10 seconds to start the I2PHelper screen!"
timeout_std 10
screen_test I2PHelper
if [ $? -lt 2 ]; then
  echo "I2PHelper screen already started!"
else
  echo "I2PHelper screen started!"
  screen -dmS I2PHelper python I2PHelper.py
fi
screen_test I2PSocksServer
if [ $? -lt 2 ]; then
  echo "I2PSocksServer screen already started!"
else
  echo "Wait 30 seconds in order to can start the I2PSocksServer screen"
  timeout_std 30
  echo "I2PSocksServer screen started!"
  screen -dmS I2PSocksServer python I2PSocksServer.py
fi
cd ..
cd ..
screen_test ZeroNet
if [ $? -lt 2 ]; then
  echo "ZeroNet screen already started!"
else
  echo "Wait 30 seconds in order to can start the ZeroNet screen"
  timeout_std 30
  echo "ZeroNet screen started!"
  screen -dmS ZeroNet python zeronet.py
fi

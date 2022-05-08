#!/bin/sh
sudo apt install python3
#install srsran dependencies
sudo apt-get install -y build-essential make cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev lksctp-tools
#install pysctp
sudo apt install -y libsctp-dev python3-dev g++
git clone https://github.com/P1sec/pysctp.git
cd pysctp
sudo python3 setup.py install
cd ..
#install pycrate
git clone https://github.com/P1sec/pycrate.git
cd pycrate
sudo python3 setup.py install
cd ..


#download and install bladeRF drivers and cli
git clone https://github.com/Nuand/bladeRF.git
sudo apt-get install -y libusb-1.0-0-dev
#LIBUSB_PATH=usr/lib/arm-linux-gnueabihf/libusb-1.0.so.0.3.0
#export LIBUSB_PATH
cd bladeRF
mkdir -p build
cd build
cmake -DENABLE_BACKEND_LIBUSB=TRUE ../
make
sudo make install
sudo ldconfig
cd ..
cd ..


#soapySDR
sudo apt-get install -y cmake g++ libpython3-dev python3-numpy swig
git clone https://github.com/pothosware/SoapySDR.git
cd SoapySDR
mkdir build
cd build
cmake ..
make -j4
sudo make install
sudo ldconfig #needed on debian systems
#SoapySDRUtil --info
cd ..
cd ..

#download and build srsRAN
git clone https://github.com/srsRAN/srsRAN.git
cd srsRAN
mkdir build
cd buildf
cmake ../
make
make test
#install srsRAN
sudo make install
sudo ldconfig
srsran_install_configs.sh user
cd ..
cd ..

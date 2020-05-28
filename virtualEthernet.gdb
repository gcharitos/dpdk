#sudo gdb ./x86_64-native-linuxapp-gcc/app/testpmd
set args l 0-1  -- --port-topology=chained --auto-start --stats-period=3 --forward-mode=spp-eni-addr-swap

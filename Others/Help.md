# Features
- For Bitcoin use ```--coin BTC``` and for Ethereum use ```--coin ETH```
- Single address(rmd160 hash) for BTC or ETH address searching with mode ```-m ADDREES```
- Multiple addresses(rmd160 hashes) or ETH addresses searching with mode ```-m ADDREESES```
- XPoint[s] mode is applicable for ```--coin BTC``` only
- Single xpoint searching with mode ```-m XPOINT```
- Multiple xpoint searching with mode ```-m XPOINTS```
- For XPoint[s] mode use x point of the public key, without 02 or 03 prefix(64 chars).
- Cuda only.

# Usage
- For multiple addresses or xpoints, file format must be binary with sorted data.
- To convert Bitcoin addresses list(text format) to rmd160 hashes binary file use provided python script ```addresses_to_hash160.py```
- To convert pubkeys list(text format) to xpoints binary file use provided python script ```pubkeys_to_xpoint.py```
- To convert Ethereum addresses list(text format) to keccak160 hashes binary file use provided python script ```eth_addresses_to_bin.py```
- After getting binary files from python scripts, use ```BinSort``` tool provided with KeyHunt-Cuda to sort these binary files.
- Don't use XPoint[s] mode with ```uncompressed``` compression type.
- CPU and GPU can not be used together, because the program divides the whole input range into equal parts for all the threads, so use either CPU or GPU so that the whole range can increment by all the threads with consistency.
- Minimum entries for bloom filter is >= 2.
- For Multi GPUs use ```Rotor-Cuda.exe -g --gpui 0,1,2 --gpux 256,256,256,256,256,256 -m addresses --coin BTC --range 1:1fffffffff -i test.bin```
- For Multi GPUs autogrid use ```Rotor-Cuda.exe -g --gpui 0,1,2 -m addresses --coin BTC --range 1:1fffffffff -i test.bin```
- If you have a weak GPU or driver error, remove **--gpux 256,256** the Grid will automatically assign.

## Rotor-Cuda
Run ```Rotor-Cuda.exe -h```

```
C:\Users\user>Rotor-Cuda.exe -h
Rotor-Cuda [OPTIONS...] [TARGETS]
Where TARGETS is one address/xpont, or multiple hashes/xpoints file

-h, --help                               : Display this message
-c, --check                              : Check the working of the codes
-u, --uncomp                             : Search uncompressed points
-b, --both                               : Search both uncompressed or compressed points
-g, --gpu                                : Enable GPU calculation
--gpui GPU ids: 0,1,...                  : List of GPU(s) to use, default is 0
--gpux GPU gridsize: g0x,g0y,g1x,g1y,... : Specify GPU(s) kernel gridsize, default is 8*(Device MP count),128
-t, --thread N                           : Specify number of CPU thread, default is number of core
-i, --in FILE                            : Read rmd160 hashes or xpoints from FILE, should be in binary format with sorted
-o, --out FILE                           : Write keys to FILE, default: Found.txt
-m, --mode MODE                          : Specify search mode where MODE is
                                               ADDRESS  : for single address
                                               ADDRESSES: for multiple hashes/addresses
                                               XPOINT   : for single xpoint
                                               XPOINTS  : for multiple xpoints
--coin BTC/ETH                           : Specify Coin name to search
                                               BTC: available mode :-
                                                   ADDRESS, ADDRESSES, XPOINT, XPOINTS
                                               ETH: available mode :-
                                                   ADDRESS, ADDRESSES
-l, --list                               : List cuda enabled devices
--range KEYSPACE                         : Specify the range:
                                               START:END
                                               START:+COUNT
                                               START
                                               :END
                                               :+COUNT
                                               Where START, END, COUNT are in hex format
-r, --rkey Rkey                          : Reloads random start Private key every (-r 10 = 10.000.000.000), default is disabled
-c, --check                              : Check the working of the codes
-n, --next                               : Range mode GPU save checkpoints every -n ? minutes (1-10000) Default: false
-n, --next                               : Random mode: What bit range to randomize? -n 1-256 Example -n 252 Default: 252-256 bit
-z, --zet                                : Random mode: End range for random. Example -n 48 -z 52 (random in 48,49,50,51,52 bit) Default: false
-d, --display                            : Disable all informers, compact version for many GPUs. Use -d 0 Default -d 1 (display all)
```
##### Linux
 - Edit the makefile and set up the appropriate CUDA SDK and compiler paths for nvcc. Or pass them as variables to `make` command.
 - Install libgmp: ```sudo apt install -y libgmp-dev```

    ```make
    CUDA       = /usr/local/cuda-11.0
    CXXCUDA    = /usr/bin/g++
    ```
 - To build CPU-only version (without CUDA support):
    ```sh
    $ make all
    ```
 - To build with CUDA: pass CCAP value according to your GPU compute capability
    ```sh
    $ cd Rotor-Cuda
    $ make gpu=1 CCAP=75 all
    ```
#### BinSort
```sh
$ cd BinSort
$ make
```

# Fialka [M-125](https://en.wikipedia.org/wiki/Fialka)
## GPU & CPU Brute-force BitCoin Private keys WIF, Minikeys, Passphrases....
![alt text](https://raw.githubusercontent.com/phrutis/LostCoins/main/Others/4.jpg "Fialka M-125")
- This is a modified version of [LostCoins](https://github.com/phrutis/LostCoins/) 
- Huge thanks to [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in Fialka M-125.
## Quick start
- Сonvert 1... addresses to RIPEMD160 binary hashes using [b58dec.exe](https://github.com/phrutis/Fialka/blob/main/Others/b58dec.exe) ```b58dec.exe addresses.txt base160.bin```
- It is important to sort the base160.bin file or else the Bloom search filter will not work as expected.
- To SORT base160.bin use the program [RMD160-Sort.exe](https://github.com/phrutis/Fialka/blob/main/Others/RMD160-Sort.exe) ```RMD160-Sort.exe base160.bin hex160-Sort.bin``` 
# Parametrs:
Run: ```Fialka.exe -h```
```
Usage: Fialka M-125 [options...]
Options:
    -v, --version          Print version. For help visit https://github.com/phrutis/Fialka
    -u, --uncomp           Search only uncompressed addresses 
    -b, --both             Search both (uncompressed and compressed addresses)
    -g, --gpu              Enable GPU calculation
    -i, --gpui             GPU ids: 0,1...: List of GPU(s) to use, default is 0
    -x, --gpux             GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number),128
    -t, --thread           CPU number of cores and threads
    -o, --out              Output results Found to the specified text file. Default: Found.txt
    -m, --max              -m 1-256 Range bit limiter
    -s, --seed             Text file name or other
    -z, --zez              Additional meaning or other
    -e, --nosse            Disable SSE hash function
    -r, --rkey             Number of Modes
    -n, --nbit             Number of letters or other
    -f, --file             RIPEMD160 binary SORT hash file path with addresses 1... 
    -h, --help             Shows this page
 ```
## Mode 0 
- [Use old databases or a generator to create list of passphrases, minikeys, WIF, HEX](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md) 
- The list of found passphrases is [here](https://privatekeys.pw/brainwallet/bitcoin/1) and [here](https://allprivatekeys.com/hacked-brainwallets-with-balance)
- There is a premade file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) 8 words of 3 letters can be found inside
- Uncomressed: cat, gaz, for, car 
- Compressed: abc, cop, run, zip
- [Make your own](https://brainwalletx.github.io/) passphrase or minikeys for test
- There is a premade file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) 8 WIF can be found inside: 
- 4 WIF uncomressed: </br>
5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81 </br>
5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE </br>
5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7 </br>
5J9J63iW7s5p54T569qstediqNgBTLXpUmxUtQwsXTaHz3JCsKt </br>
- 4 WIF compressed: </br>
L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm </br>
L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF </br>
L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG </br>
KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj </br>
- [Make your own](https://secretscan.org/PrivateKeyWif) WIF or HEX for test
- For searching for uncompressed WIF 5.. (51 length) use the **-b** parameter!

### Find passphrases, minikeys and private keys from a text file
- Works only in CPU
- -t ? amount of cores (threads) to use? 1-11 max
- If CPU has 64 cores, you can run 6 copies of the program -t 10 with different dictionaries.txt 
- For text files less than 100,000 use -t 1 
- Maximun amount of lines in text file is 2,147,483,647 on a new line 
- If the file is larger than that, cut into EmEditor chunks by 2,000,000,000 lines 
- The last two lines in the file are **DISCARDED**! 

#### To search for passphrases, use -u or -b
- For passphrases use only letters and symbols: A-Za-z0-9А-Яа-яёЁьЪЬъ \`~!@#$&\*()-\_=+{}|;:'<>,./? others will be skipped!
- Run: ```Fialka.exe -b -t 1 -r 0 -s Dictionaries.txt -z Passphrases -f test.bin``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r0.jpg "Fialka M-125")

#### To search for [minikeys](https://en.bitcoin.it/wiki/Mini_private_key_format)
 - For minikeys S... (length 22) or S... (length 30)
 - Run: ```Fialka.exe -t 1 -r 0 -s Minikeys-list.txt -z Passphrases -f test.bin```

#### To search for private keys WIF
 - For WIF **ONLY!** letters Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)
 - For WIF the first letter must be L... (length 52) and K... (length 52) or 5... (length 51) if 5.. WIF is listed use **-b**
 - Run: ```Fialka.exe -t 1 -r 0 -s Private-keys-wif.txt -z WIF -f test.bin```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/0wif.jpg "Fialka M-125")

#### To search for private keys HEX
 - For HEX use only 0,1,3,4,5,6,7,8,9,a,b,c,d,e,f length 1-64 max)
 - Run: ```Fialka.exe -t 1 -r 0 -s Private-keys-hex.txt -z HEX -f test.bin```
 
![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r0hex.jpg "Fialka M-125")

## Mode 1
### Random search WIF from puzzle 64 bit
- VanitySearch search the prefix 16jY7qLJ from a [puzzles 64 bits](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) 
- Example WIF out:
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYvQqYKVuZryGJLxfH1P </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwJvoHMhmXgVkKmTcAx </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwYTCAfXHKuFsZ2stFG </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwyWFyQr5iVJkTvXccg </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVeYFPidEza7Td </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ3hA1yqkkqoyqype3pQ </br>
**KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4CZMY**vJden3dEAzBrN </br>
- We know that the private key corresponds to 64 bits. Therefore, set the -m 64 range bit limiter.
- If the output private key is more or less than 64 bits, skip... 
- For 256 bit range use -m 256 or other ranges skip...
- -n ? amount of random letters. If prefix 38 letters 52-38 = -n 14
- Run: ```Fialka.exe -t 6 -r 1 -f puzles.bin -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ4CZMY -n 12 -m 64```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1.jpg "Fialka M-125")

## Mode 2
### Parallel search for WIF with continuation
#### **[How to use mode 2 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r2.md)**
Run: ```Fialka.exe -t 6 -r 2 -f test.bin -m 64 -n 45``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r2.jpg "Fialka M-125")

## Mode 3
### Parallel search for passphrases with continuation + filter
#### **[How to use mode 3 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r3.md)**
Run: ```Fialka.exe -t 6 -r 3 -f test.bin -n 60``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r3.jpg "Fialka M-125")

## Mode 4
### Parallel search for passphrases with continuation + filter
#### **[How to use mode 4 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r4.md)**
Run: ```Fialka.exe -t 6 -r 4 -f test.bin -n 60``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r4.jpg "Fialka M-125")

## Mode 5
### Parallel search for passphrases with continuation + Filter
#### **[How to use mode 5 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r5.md)**
Run: ```Fialka.exe -t 6 -r 5 -f test.bin -n 60``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r5.jpg "Fialka M-125")

## Mode 6
### Parallel search for WIF with continuation (without range limiter -m)
#### Similar [settings as in mode 2](https://github.com/phrutis/Fialka/blob/main/Others/img/r2.md) without range limiter -m
Run: ```Fialka.exe -t 6 -r 6 -f test.bin -n 45``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r6.jpg "Fialka M-125")

## Mode 7
### Parallel search for minikeys S.. with continuation
Create file Minikeys.txt 
Add Minikeys S... (22) or S.. (30) on a new line. One line = 1 thread (-t 1) max -t 64</br> 
Run: ```Fialka.exe -t 6 -r 7 -f test.bin```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r7.jpg "Fialka M-125")

## Mode 8
### GPU Parallel WIF search
Create a text file WIF.txt with 65536 WIF on a new line. </br>
Run: ```Fialka.exe -t 0 -g -i 0 -x 256,256 -r 8 -f test.bin```

![Mode 8 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r8.jpg "Fialka M-125")

# VanitySearch special edition for Fialka M-125
Example address [puzzle 64](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) **16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN** </br>
The longer found prefix is, the more accurate is the WIF </br>
You can specify the exact range for the WIF search. </br>
Use start and finish options to randomize between them. </br>
The output creates 2 files: Found.txt and NEW-WIF.txt (only WIF is sorted)</br>

Search for WIF from prefix **16jY7qLJn**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -start 8000000000000000 -finish ffffffffffffffff -o Found.txt 16jY7qLJn```</br></br>
Search for WIF from prefix **16jY7qLJnx**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -start 8000000000000000 -finish ffffffffffffffff -o Found.txt 16jY7qLJnx```</br></br>
Search for WIF from prefix **16jY7qLJnxb**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -start 8000000000000000 -finish 9000000000000000 -o Found.txt 16jY7qLJnxb```

![Mode 8 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/vanitysearch.jpg "Fialka M-125")

## Building
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
## License
LostCoins is licensed under GPL v3.0
## Disclaimer
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.

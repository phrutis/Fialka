# Fialka [M-125](https://en.wikipedia.org/wiki/Fialka)
## Brute-force BitCoin private keys, WIF, minikeys and passphrases.
![alt text](https://raw.githubusercontent.com/phrutis/LostCoins/main/Others/4.jpg "Fialka M-125")
- This is a modified version of [Rotor-Cuda](https://github.com/phrutis/Rotor-Cuda) 
- Huge thanks to [kanhavishva](https://github.com/kanhavishva) and to all developers whose codes were used in Fialka M-125.
## Quick start
- [**How to create base addresses hex160Sort.bin**](https://github.com/phrutis/Fialka/tree/main/Others)
## Parametrs:
- -t ? amount of CPU cores (threads) to use?
- -r ? search mode number
- In any mode, you can use one of the options below:
- Bitcoin Single Addres use: ```-m address --coin BTC 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Bitcoin Multi Address use: ```-m addresses --coin BTC -i test.bin```
- ETHEREUM Single Addres use: ```-m address --coin eth 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
- ETHEREUM Multi Address use: ```-m addresses --coin eth -i base160_eth_sorted.bin```
- Public key Single X Point use: ```-m xpoint --coin BTC a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- Public keys Multi X Points use: ```-m xpoints --coin BTC -i Pubkeys0.1up.bin```
- Example Single Addres use: ```Fialka.exe -t 6 -r 2 -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVe -n 11 -d 64 -m address --coin BTC 16jY7qd27Snurgjj5rumgHYBEuTSARVSf6``` 
- Example Single X Point use: ```Fialka.exe -t 6 -r 2 -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVe -n 11 -d 64 -m xpoint --coin BTC cd6d186d8946f6baa4eca4bcd63deda1b0afe62939811f7ec202dc0007df16e0```
- Example Multi Address use: ```Fialka.exe -t 6 -r 2 -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVe -n 11 -d 64 -m addresses --coin BTC -i hex160Sort.bin```
- [Use old databases or a generator to create list of passphrases, minikeys, WIF, HEX](https://github.com/phrutis/LostCoins/blob/main/Others/Modes.md) 
- The list of found passphrases is [here](https://privatekeys.pw/brainwallet/bitcoin/1) and [here](https://allprivatekeys.com/hacked-brainwallets-with-balance)
- There is a premade file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) 8 words of 3 letters can be found inside
- Uncomressed: cat, gaz, for, car 
- Compressed: abc, cop, run, zip
- [Make your own](https://brainwalletx.github.io/) passphrase or minikeys for test
- There is a premade file [test.bin](https://github.com/phrutis/Fialka/blob/main/Others/test.bin) 8 WIF can be found inside: 
- 4 WIF uncomressed: </br>
5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81</br>
5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE</br>
5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7</br>
5J9J63iW7s5p54T569qstediqNgBTLXpUmxUtQwsXTaHz3JCsKt</br>
- 4 WIF compressed:</br>
L3UBXym7JYcMX91ssLgZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm</br>
L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF</br>
L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG</br>
KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj</br>
- [Make your own](https://secretscan.org/PrivateKeyWif) WIF or HEX for test
- For searching for uncompressed WIF 5.. (51 length) use the **-b** parameter!

## Mode 1 
### Find passphrases, minikeys and private keys from a text file
- Works only in CPU
- -t ? amount of cores (threads) to use? 1-11 max
- If CPU has 64 cores, you can run 6 copies of the program -t 10 with different dictionaries.txt 
- For text files less than 100,000 use -t 1 
- Maximun amount of lines in text file is 2,147,483,647 on a new line 
- If the file is larger than that, cut into EmEditor chunks by 2,000,000,000 lines 
- The last two lines in the file are **DISCARDED**! 

#### To search for passphrases, for Uncompressed addresses use -u or -b
- For passphrases use only letters and symbols: A-Za-z0-9А-Яа-яёЁьЪЬъ \`~!@#$&\*()-\_=+{}|;:'<>,./? others will be skipped!
- Run: ```Fialka.exe -t 6 -r 1 -m addresses --coin BTC -s dictionary-words.txt -z Passphrases -i test.bin``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1p.jpg "Fialka M-125")

#### To search for BIP39 words
- For manual exact search of BIP39 word combinations 
- Runs slowly on only one core! Use -t 1 If you need faster, use copies of the Fialka M-125 program with different text files</br> 
- Use a generator to generate BIP39 word combinations. 
- Example: ```Generator.exe --dictlist "in.txt,in2.txt" --rule "$0[_]?$1" -s " " out.txt```
- Run: ```Fialka.exe -t 1 -r 1 -m address --coin BTC -s bips-list.txt -z BIP -n 5 1ASs2iVA1CCXoMGD98TDsdsoiFDDAbaqbd```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1bip.png "Fialka M-125")

#### To search for [minikeys](https://en.bitcoin.it/wiki/Mini_private_key_format)
 - For minikeys S... (length 22) use -u parameter or S... (length 30) use -b parameter
 - Run: ```Fialka.exe -b -t 6 -r 1 -m address --coin BTC -s dictionary-minikeys.txt -z Passphrases 14VkDDuvFXs8sMhqznWzioMXKbPAuLofeb```
 
 ![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1mini.png "Fialka M-125")

#### To search for private keys WIF
 - For WIF **ONLY!** letters Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)
 - For WIF the first letter must be L... (length 52) and K... (length 52) or 5... (length 51) if 5.. WIF is listed use **-b**
 - Run: ```Fialka.exe -t 6 -r 1 -m addresses --coin BTC -s dictionary-WIF.txt -z WIF -i test.bin```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1wif.jpg "Fialka M-125")

#### To search for private keys HEX
 - For HEX use only 0,1,3,4,5,6,7,8,9,a,b,c,d,e,f length 1-64 max)
 - Run: ```Fialka.exe -t 6 -r 1 -m addresses --coin BTC -s private-keys-list.txt -z HEX -i test.bin```
 
![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r1hex.jpg "Fialka M-125")

## Mode 2
### Random search WIF from puzzle 64 bit
- VanitySearch search the prefix 16jY7qLJ from a [puzzles 64 bits](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) 
- Example WIF out:</br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYvQqYKVuZryGJLxfH1P </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwJvoHMhmXgVkKmTcAx </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwYTCAfXHKuFsZ2stFG </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYwyWFyQr5iVJkTvXccg </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVeYFPidEza7Td </br>
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qZ3hA1yqkkqoyqype3pQ </br>
**KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVe**YFPidEza7Td </br>
- We know that the private key corresponds to 64 bits. Therefore, set the -d 64 range bit limiter.
- If the output private key is more or less than 64 bits, skip... 
- For 256 bit range use -d 256 or other ranges skip...
- -n ? amount of random letters. If prefix 41 letters 52-41 = -n 11
- Run: ```Fialka.exe -t 6 -r 2 -s KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYzMHHGVe -n 11 -d 64 -m address --coin BTC 16jY7qd27Snurgjj5rumgHYBEuTSARVSf6```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r2.png "Fialka M-125")

## Mode 3
### Parallel search for WIF with continuation
#### **[How to use mode 3 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r3.md)**
Run: ```Fialka.exe -t 6 -r 3 -d 64 -n 45 -m address --coin BTC 16jY7q2ZeFPaadZvdygopRURcXhwBWKsA4``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r3.png "Fialka M-125")

## Mode 4
### Parallel search for passphrases with continuation + filter
#### **[How to use mode 4 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r4.md)**
- Use the -u or -b parameter to find old passphrases </br> 
Run: ```Fialka.exe -t 6 -r 4 -m addresses --coin BTC -i test.bin -n 60```</br> 
Run: ```Fialka.exe -t 6 -r 4 -n 60 -m address --coin BTC 14Nmb7rFFLdZhKaud5h7nDSLFQfma7JCz2```</br> 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r4.jpg "Fialka M-125")

## Mode 5
### Parallel search for passphrases with continuation + filter
#### **[How to use mode 5 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r5.md)**
- Use the -u or -b parameter to find old passphrases </br> 
Run: ```Fialka.exe -t 6 -r 5 -n 60 -m addresses --coin BTC -i test.bin```</br>
Run: ```Fialka.exe -t 6 -r 5 -n 60 -m address --coin BTC 14Nmb7rFFLdZhKaud5h7nDSLFQfma7JCz2```</br>

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r5.jpg "Fialka M-125")

## Mode 6
### Parallel search for passphrases with continuation + Filter
#### **[How to use mode 6 + examples](https://github.com/phrutis/Fialka/blob/main/Others/img/r6.md)**
- Use the -u or -b parameter to find old passphrases </br> 
Run: ```Fialka.exe -t 6 -r 6 -n 60 -m addresses --coin BTC -i test.bin```</br>
Run: ```Fialka.exe -t 6 -r 6 -n 60 -m address --coin BTC 15KqNGHFEViRS4WTYYJ4TRoDtSXH5ESzW9```</br> 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r6.jpg "Fialka M-125")

## Mode 7
### Parallel search for WIF with continuation (without range limiter -d)
#### Similar [settings as in mode 3](https://github.com/phrutis/Fialka/blob/main/Others/img/r3.md) without range limiter -d
Run: ```Fialka.exe -t 6 -r 7 -n 45 -m address --coin BTC 16jY7q2ZeFPaadZvdygopRURcXhwBWKsA4``` 

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r7.png "Fialka M-125")

## Mode 8
### Parallel search for minikeys S.. with continuation
Create file Minikeys.txt 
Add Minikeys S... (22) or S.. (30) on a new line. One line = 1 thread (-t 1) max -t 64</br> 
- For minikeys S... (length 22) use -u parameter or S... (length 30) use -b parameter </br>
Run: ```Fialka.exe -t 6 -r 8 -m address --coin BTC 1KM1Wq1boMka4M4vavQX5Zyc281G8SbuCQ```

![alt text](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r8.png "Fialka M-125")

## Mode 9
### GPU Parallel WIF search
The mode is under testing, to search for WIFs on the GPU, use the previous version of Fialka!!! </br>
Create a text file WIF.txt with 65536 WIF on a new line. 
The GPU is under development! Use the mode in the old version of the [Fialka v1.0](https://github.com/phrutis/Fialka/releases/tag/v1.0)</br>
Run: ```Fialka.exe -t 0 -g -i 0 -x 256,256 -r 8 -f test.bin```

![Mode 9 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r9.jpg "Fialka M-125")

## Mode 10
### Random search for minikeys 22 S...
Run: ```Fialka.exe -u -t 6 -r 10 -m addresses --coin BTC -i test.bin```

![Mode 10 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r10.jpg "Fialka M-125")

## Mode 11
### Random search for minikeys 30 S...
Run: ```Fialka.exe -b -t 6 -r 11 -m addresses --coin BTC -i test.bin```

![Mode 11 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r11.jpg "Fialka M-125")

## Mode 12
### Random search for minikeys 22, 30 S...
- -s ? the first part of the key S.....</br>
- -n ? how many letters to randomize? </br>
- -z second part of the key (you can do without it) </br>
- For minikeys S... (length 22) use -u parameter or S... (length 30) use -b parameter</br>
Run: ```Fialka.exe -u -t 6 -r 12 -s SHwfehdFcL -n 3 -z 2ieZEtK -m address --coin BTC 1GWPWQNWdnYQYuo4DPzEhFCKhKq8dxGYSG```

![Mode 12 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r12.png "Fialka M-125")

## Mode 13 (best performance)
### Random search for minikeys 22, 30 S... (Analog mode 12)
- Checking minikays for validity "V" (? = 0x00...) If the mini-key is not valid then skip...
- -s ? the first part of the key S.....</br>
- -n ? how many letters to randomize? </br>
- -z second part of the key (you can do without it) </br>
- For minikeys S... (length 22) use -u parameter or S... (length 30) use -b parameter</br>
Run: ```Fialka.exe -u -t 1 -r 13 -s SYXqbKXyX -n 4 -z 3cSMV7Csa -m address --coin BTC 1KM1Wq1boMka4M4vavQX5Zyc281G8SbuCQ```</br>
if full random:</br>
Run: ```Fialka.exe -u -t 6 -r 13 -s S -n 21 -m addresses --coin BTC -i test.bin```

![Mode 13 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r13.png "Fialka M-125")

## Mode 14 (MAX -t 12)
### Parallel search for WIF with continuation + filter AAA -> AAB + checksum check 
#### -n ? ex. -n 38 = Movable part wif (38) + fixed part (13)
#### Example Create a text file WIF.txt with 6 WIF on a new line. </br>
5JiznUZskJpwodP3SR85vx5JKeopA3QpTK13BuziW8RmGGyJg81</br>
5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJo4jpQ2YTNdPZ1CbuE</br>
5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ318b4CR1v6YUVLu2D7</br>
L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac11uRVsYb9hjesWBxuF</br>
L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2avYKwRrCCAmi2NirDG</br>
KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJaKNaRArZME5fpfAjWj</br>
Run: ```Fialka.exe -b -t 6 -r 14 -n 38 -m addresses --coin BTC -i test.bin``` 

```
C:\Users\BOSS>Fialka.exe -b -t 6 -r 14 -n 38 -m addresses --coin BTC -i test.bin

  Fialka M-125 (17.01.2022) v4.0

  COMP MODE    : COMPRESSED & UNCOMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  BTC HASH160s : test.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 75,471 Bitcoin addresses

  Bloom at     : 000002733EFF7FC0
  Version      : 2.1
  Entries      : 150942
  Error        : 0.0000010000
  Bits         : 4340363
  Bits/Elem    : 28.755175
  Bytes        : 542546 (0 MB)
  Hash funcs   : 20


  Start Time   : Mon Jan 17 17:32:56 2022

  Mode         : 14
  Rotor        : Paralleland sequential search for WIF values. MAX -t 12, 1 core = 1 line
  Rotor        : Save checkpoints every 5 minutes in NEXT-WIF.txt
  Rotor        : Activated filter-replacement of 3 identical letters (AAA->AAB) every 1 minute
  Rotor        : If the checksum (32 bit) does not equal the private key, skip...
  Rotor        : Movable part wif (38) + fixed part (13)
  Start WIF(1) : 5JiznUZskJpwodP3SR85vx5JKeopA3QpTK13Bu+[ziW8RmGGyJg81]
            ...
  Start WIF(6) : KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJaKNaRArZME5fpfAjWj
  Site         : https://github.com/phrutis/Fialka
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9



  Valid WIF: 5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7

  =================================== FOUND! ===================================
  Address   : 19JxMTT1YqVHAx16NdvgULNajRYvrbFjm1
  Priv (WIF): p2pkh: 5HwfeuhdFscL9YTQCLT2952dieZEtKbzJ328b4CR1v6YUVLu2D7
  Priv (HEX): 10C22BCF4C768B515BE4E94BCAFC71BF3E8FB5F70B2584BCC8C7533217F2E7F9
  PubK (HEX): 04BEC831D2E490FB784CB48284E102B80FF84EC3E0F2F69806002134D166B1B998CD1A8043AEDFBC2D2C76C8E0934404B1A7C38D6737FD94EFBC0E26C58BA94651
  ==============================================================================

  Valid WIF: L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF

  =================================== FOUND! ===================================
  Address   : 15KqNGHFEViRS4WTYYJ4TRoDtSXH5ESzW9
  Priv (WIF): p2pkh: L3BEabkqcsppnTdzAWiizPEuf3Rvr8QEac21uRVsYb9hjesWBxuF
  Priv (HEX): B1C02B717C94BD4243E83B5E98BA37FB273BC035E4AD8FC438EA4D07A1043F56
  PubK (HEX): 03ABC0DD6E7AFD2D884118807FB129C33ABA0AE28E075BF01346BBAF016F86DBD8
  ==============================================================================
  [00:00:03] [5JiznUZskJpwodP3SR85vx5JKeopA3QpTK5UhdziW8RmGGyJg81] [CPU: 1.42 Mk/s] [F: 2] [V: 2] [Skip: 4,327,630]
  Valid WIF: 5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE

  =================================== FOUND! ===================================
  Address   : 1ERNpuxsGB6ytQKTwtCSmeyBTzmyw3uQAG
  Priv (WIF): p2pkh: 5KMdQbcUFS3PBbC6VgitFrFuaca3gBY4BJt4jpQ2YTNdPZ1CbuE
  Priv (HEX): CADC8EDAB738C1DF2CE192AF17E7D35EBBDCAF075E32ED2CC86F6D97C160DBAE
  PubK (HEX): 04AD0831DB6C686A67D03EC1087F05548B38EFA2E6225DC5DF317D901A312E133FC766AD786ABAE17EC1AD30DF4E410FEFB81EF445F25F0C95BD03AB5A0DF87193
  ==============================================================================
  [00:00:04] [5JiznUZskJpwodP3SR85vx5JKeopA3QpTK6WEFziW8RmGGyJg81] [CPU: 1.36 Mk/s] [F: 3] [V: 3] [Skip: 5,510,681]
  Valid WIF: 5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81

  =================================== FOUND! ===================================
  Address   : 162TRPRZvdgLVNksMoMyGJsYBfYtB4Q8tM
  Priv (WIF): p2pkh: 5JiznUZskJpwodP3SR85vx5JKeopA3QpTK63BuziW8RmGGyJg81
  Priv (HEX): 77AF778B51ABD4A3C51C5DDD97204A9C3AE614EBCCB75A606C3B6865AED6744E
  PubK (HEX): 04A45EBC40F95CC06EF93A5F5E9DAA22774A5C9A120AC14D87C328B44C1158F81CDDD109246A4D8BFF5F93CBBA79A17F2DC6E7C73DA8D6BD0D98615D1BF353F8BE
  ==============================================================================
  [00:00:07] [5JiznUZskJpwodP3SR85vx5JKeopA3QpTK9i9hziW8RmGGyJg81] [CPU: 1.33 Mk/s] [F: 4] [V: 4] [Skip: 9,415,604]
  Valid WIF: KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj

  =================================== FOUND! ===================================
  Address   : 1Mfw1us14DXJ8ju88iewjt48tswqEshU62
  Priv (WIF): p2pkh: KyiR31LZTQ2hk1DRxEticnsQCA8tjFZcgJiKNaRArZME5fpfAjWj
  Priv (HEX): 4A70FE9AA6436E02C2DEA340FBD1E352E4EF2D8CE6CA52AD25D4B95471FC8BF2
  PubK (HEX): 03ED88FB3173D3ADCAABC0D49745E3946792B7CB92024E93966FB57511BFF853BE
  ==============================================================================
  [00:00:12] [5JiznUZskJpwodP3SR85vx5JKeopA3QpTLFC1kziW8RmGGyJg81] [CPU: 1.30 Mk/s] [F: 5] [V: 5] [Skip: 16,052,967]
  Valid WIF: L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG

  =================================== FOUND! ===================================
  Address   : 14Nmb7rFFLdZhKaud5h7nDSLFQfma7JCz2
  Priv (WIF): p2pkh: L31UCqx296TVRtgpCJspQJYHkwUeA4o3a2pvYKwRrCCAmi2NirDG
  Priv (HEX): ACBA25512100F80B56FC3CCD14C65BE55D94800CDA77585C5F41A887E398F9BE
  PubK (HEX): 024D7F6D07FC4FD8DE5F08B8CF5B3C1B8A0B9C0B28F18EBEC39C6DC35E3AD22573
  ==============================================================================
  [00:00:36] [5JiznUZskJpwodP3SR85vx5JKeopA3QpTLhZE8ziW8RmGGyJg81] [CPU: 1.14 Mk/s] [F: 6] [V: 6] [Skip: 46,706,108]
  ```
## Mode 15
### Random search part WIF + checksum check
- -s ? part1 (maybe without the first part) 
- -n ? how many random letters 
- -z ? part2 or checkeum (possible without the second part) </br>

Run: ```Fialka.exe -t 6 -r 15 -s L3UBXym7JYcMX91 -n 4 -z ZzS2MvxTxjU3VRf9S4jJWXVFdDi4NsLcm -m addresses --coin BTC -i test.bin``` 
![Mode 15 example](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/r15.png "Fialka M-125")

# VanitySearch special edition for Fialka M-125
Example address [puzzle 64](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) **16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN** </br>
The longer found prefix is, the more accurate is the WIF </br>
You can specify the exact range for the WIF search. </br>
Use start and finish options to randomize between them. </br>
The output creates 2 files: Found.txt and NEW-WIF.txt (only WIF is sorted)</br>

Search for WIF from prefix **16jY7qLJn**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -bit 64 -start 8000000000000000 -finish ffffffffffffffff -o Found.txt 16jY7qLJn```</br></br>
Search for WIF from prefix **16jY7qLJnx**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -bit 64 -start 8000000000000000 -finish ffffffffffffffff -o Found.txt 16jY7qLJnx```</br></br>
Search for WIF from prefix **16jY7qLJnxb**</br>
Run: ```VanitySearch.exe -t 0 -gpu -g 256,256 -r 25000 -bit 64 -start 8000000000000000 -finish 9000000000000000 -o Found.txt 16jY7qLJnxb```

![VanitySearch](https://raw.githubusercontent.com/phrutis/Fialka/main/Others/img/vanitysearch.png "Fialka M-125")

## Building
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9
## License
LostCoins is licensed under GPL v3.0
## Disclaimer
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.

## How to create a base of addresses 

- Downloading the fresh database of addresses [here](https://blockchair.com/dumps)
- We take Legacy addresses starting with 1xxx... from the base and create a list addresses.txt
- Converting addresses to RMD160 binary format:
- Install base58 ```python -m pip install base58```
- Use Python: ```python addresses_to_hash160.py addresses.txt hax160.bin```
- if there is no python Windows: ```b58dec.exe addresses.txt hex160.bin```
- Next, you need to sort the base hex160.bin
- CMD: ```BinSort.exe 20 hex160.bin hex160sorted.bin```
- Or another program CMD: ```RMD160-Sort.exe hex160.bin hex160sorted.bin```
- For the test, you can use a ready-made base [puzzle_1_37_hash160_out_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/puzzle_1_37_hash160_out_sorted.bin)

## How to create a base of Ethereum addresses 

- Downloading the fresh database of ethereum addresses [here](https://blockchair.com/dumps)
- Use Python: ```python eth_addresses_to_bin.py eth_addresses_in.txt eth_addresses_out.bin```
- Next, you need to sort the base eth_addresses_out.bin
- CMD: ```BinSort.exe 20 eth_addresses_out.bin eth_addresses_sotrted.bin```
- Or another program CMD: ```RMD160-Sort.exe eth_addresses_out.bin eth_addresses_sorted.bin```
- For the test, you can use a ready-made base [puzzle_1_37_addresses_eth_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/puzzle_1_37_addresses_eth_sorted.bin)

## How to create a base of Public keys for Multi X Points mode

- Downloading the fresh database of addresses [here](https://blockchair.com/dumps)
- We take Legacy addresses starting with 1xxx... from the base and create a list addresses.txt
- Use Python: ```Pub-from-blockchain.py``` (addresses.txt file is created pubkeys.txt) (speed limit 50 address in 60 sek)
- Or manually use the link [https://blockchain.info/q/pubkeyaddr/1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ](https://blockchain.info/q/pubkeyaddr/1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ)
- Since the search is compressed, public keys starting with 02 and 03 are suitable for it. 
- You can use public keys from Uncompressed addresses 04 (128 characters). The script converts them to a compressed format.
- If the program finds such a public key, it will give a compressed address. Using the found private key, generate a positive uncompressed address
- Convert public keys (02,03,04) use Python: ```python pubkeys_to_xpoint.py pubkeys_in.txt xpoints_out.bin```
- Make sure to sort the base CMD: ```BinSort.exe 32 xpoints_out.bin Xpoints_Sorted.bin```
- For the test, you can use a ready-made base [xpoints_1_37_out_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/xpoints_1_37_out_sorted.bin)
- Public keys for puzzles single use:
- **120** 17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT **ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630**
- **125** 1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5 **33709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e**
- **130** 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua **633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852**
- **135** 16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v **145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16**
- **140** 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo **1f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640**
- **145** 19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg **afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5**
- **150** 1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy **137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49**
- **155** 1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ **5cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6**
- **160** 1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv **e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673**
---
- It takes a long time to get public addresses from the blockchain. 
- It took me a week to get all public keys from [1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.txt). It will take a month to get from [0.1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.txt).
- In the Others folder there are 2 files ([Pubkeys1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.bin) and [Pubkeys0.1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.bin)) with ready-made bin databases for Multi X Points mode. 
- **Good luck in finding**  

#include "Fialka.h"
#include "GmpUtil.h"
#include "SECP256k1.h"
#include "sha256.cpp"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include <cstring>
#include <cmath>
#include <stdexcept>
#include <cassert>
#include <algorithm>
#include <iostream>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <stdlib.h>
//#include <conio.h>

#include <vector>
#include <random>
#include <ctime>
#include <iomanip>
#include <atomic>
#include <mutex>
#include <thread>
#include <fstream>
#include <iterator>
#include <regex>
#include <string>
#include <cstdlib>
#include <ctime>
#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;
vector <char> alreadyprintedcharacters;
Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

Fialka::Fialka(const std::string& inputFile, int compMode, std::string& seed, std::string& zez, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit, int nbit2, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->inputFile = inputFile;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->rekey = rKey;
	this->nbit = nbit;
	this->nbit2 = nbit2;
	this->zet = zet;
	this->seed = seed;
	this->zez = zez;
	this->diz = diz;
	this->display = display;
	this->stroka = stroka;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->rangeDiffcp.Set(&this->rangeDiff2);
	this->lastrKey = 0;

	secp = new Secp256K1();
	secp->Init();

	// load file
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->inputFile.c_str(), "rb");
	if (!wfd) {
		printf("  %s can not open\n", this->inputFile.c_str());
		exit(1);
	}
#ifdef WIN64
	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
#else
	fseek(wfd, 0, SEEK_END);
	N = ftell(wfd);
#endif

	int K_LENGTH = 20;
	if (this->searchMode == (int)SEARCH_MODE_MX)
		K_LENGTH = 32;

	N = N / K_LENGTH;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * K_LENGTH);
	memset(DATA, 0, N * K_LENGTH);

	uint8_t* buf = (uint8_t*)malloc(K_LENGTH);;

	bloom = new Bloom(2 * N, 0.000001);

	uint64_t percent = (N - 1) / 100;
	uint64_t i = 0;
	printf("\n");
	while (i < N && !should_exit) {
		memset(buf, 0, K_LENGTH);
		memset(DATA + (i * K_LENGTH), 0, K_LENGTH);
		if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			bloom->add(buf, K_LENGTH);
			memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			if ((percent != 0) && i % percent == 0) {
				printf("\r  Loading      : %llu %%", (i / percent));
				fflush(stdout);
			}
		}
		i++;
	}
	fclose(wfd);
	free(buf);

	if (should_exit) {
		delete secp;
		delete bloom;
		if (DATA)
			free(DATA);
		exit(0);
	}

	BLOOM_N = bloom->get_bytes();
	TOTAL_COUNT = N;
	targetCounter = i;
	if (coinType == COIN_BTC) {
		if (searchMode == (int)SEARCH_MODE_MA)
			printf("\n  Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
		else if (searchMode == (int)SEARCH_MODE_MX)
			printf("\n  Loaded       : %s Bitcoin xpoints\n", formatThousands(i).c_str());

	}
	else {
		printf("\n  Loaded       : %s Ethereum addresses\n", formatThousands(i).c_str());
	}
	printf("\n");

	bloom->print();
	printf("\n");

	InitGenratorTable();

}

// ----------------------------------------------------------------------------

Fialka::Fialka(const std::vector<unsigned char>& hashORxpoint, int compMode, std::string seed, std::string zez, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit, int nbit2, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->rekey = rKey;
	this->zet = zet;
	this->display = display;
	this->stroka = stroka;
	this->seed = seed;
	this->zez = zez;
	this->diz = diz;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffcp.Set(&this->rangeDiff2);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->targetCounter = 1;
	this->nbit = nbit;
	this->nbit2 = nbit2;
	secp = new Secp256K1();
	secp->Init();

	if (this->searchMode == (int)SEARCH_MODE_SA) {
		assert(hashORxpoint.size() == 20);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)hash160Keccak)[i] = hashORxpoint.at(i);
		}
	}
	else if (this->searchMode == (int)SEARCH_MODE_SX) {
		assert(hashORxpoint.size() == 32);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)xpoint)[i] = hashORxpoint.at(i);
		}
	}
	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void Fialka::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G
	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("  Start Time   : %s", ctimeBuff);
	if (rekey == 1) {

		if (zez == "HEX") {
			printf("\n  Mode         : %.0f \n  Rotor        : Loading Private keys (HEX) from file: %s ...", (double)rekey, seed.c_str());
		}

		if (zez == "WIF") {
			printf("\n  Mode         : %.0f \n  Rotor        : Loading Private keys (WIF L,K,5) from file: %s ...", (double)rekey, seed.c_str());
		}

		if (zez == "Passphrases") {
			printf("\n  Mode         : %.0f \n  Rotor        : Loading Passphrases from file: %s ...", (double)rekey, seed.c_str());
		}

		ifstream ifs2(seed);
		int n = 0;
		string s;
		while (getline(ifs2, s)) {
			n++;

			if (n > 2147000000) {
				printf("  The file %s has more lines than 2,147,483,647 !!! Split the file into chunks 2,000,000,000 lines in EmEditor\n", seed.c_str());
				exit(1);
			}

		}
		ifs2.close();
		stope += n - 2;
		kusok = n / nbit2;
		printf("ok \n");

		if (zez == "HEX") {
			printf("  Loaded       : %d HEX private keys \n", stope);
		}
		if (zez == "WIF") {
			printf("  Loaded       : %d WIF (L,K,5) private keys \n", stope);
		}
		if (zez == "Passphrases") {
			printf("  Loaded       : %d Passphrases \n", stope);
			printf("  Rotor        : Only letters and symbols: A-Za-z0-9À-ßà-ÿ¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./? others will be Skipped!\n");

		}


		printf("  Rotor        : For files up to 100,000 use -t 1 For large file max to 2,147,483,647 lines use -t 1-11 max \n");

		if (nbit2 > 11) {
			printf("  Rotor CPU    : Only 11 cores -t 11 MAX!!! You are using (%d) cores!!! USE max -t 1-11 \n\n", nbit2);
			exit(1);
		}
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");

	}

	if (rekey == 2) {
		printf("\n  Mode         : %.0f \n", (double)rekey);

		printf("  Rotor        : Check private keys only %d (bit) (others will be skipped, use -m 1-256, default -d 64) \n", display);
		printf("  WIF          : %s \n", seed.c_str());
		printf("  Value        : %d x (1-Z Base58) \n", nbit);
		printf("  Example      : %s + %d random 1-Z Base58\n", seed.c_str(), nbit);
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 3) {
		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search for WIF values. MAX -t 64, 1 core = 1 line\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-WIF.txt\n");
		printf("  Rotor        : Check private keys only in %d (bit) (others will be skipped, use -d 1-256, default -d 64) \n", display);
		printf("  Rotor        : Identical consecutive private keys on exit from WIF will be skipped \n");

		ifstream file7777("WIF.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);

			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file WIF.txt line %d is empty!!! \n  1 core = 1 line with WIF private keys L,K,5! \n  %d cores = %d WIF private keys in the WIF.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}
			if (s7777[0] == 'K' || s7777[0] == 'L' || s7777[0] == '5') {

			}
			else {
				printf("\n  Rotor        : WIF private key starts with L,K,5 check file WIF.txt \n  This is %s NOT a WIF!\n  Check in the text file WIF.txt line %d  \n\n", s7777.c_str(), i + 1);
				exit(1);
			}
			if (s7777.length() > 52 || s7777.length() < 51) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : WIF private key on line %d has the wrong length of %d letters!\n  Uncompressed WIF 5.. (51 letters) \n  Compressed WIF L..,K.. (52 letters) \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {

				if (nbit == 0) {
					str0 = s7777;
					printf("  Start WIF(1) : %s \n", str0.c_str());
				}
				else {
					str0 = s7777.substr(0, nbit);
					int konec = s7777.length();
					int shte = konec - nbit;
					kstr0 = s7777.substr(nbit, konec);
					printf("  Rotor        : Movable part wif (%d) + fixed part (%d) \n", nbit, shte);
					printf("  Start WIF(1) : %s+[%s]\n", str0.c_str(), kstr0.c_str());
				}

			}
			if (i == nbit2 - 1) {

				if (nbit == 0) {
					printf("              ... \n");
					printf("  Start WIF(%d) : %s \n", nbit2, s7777.c_str());
				}
			}

			if (i == 1) {

				if (nbit == 0) {
					str1 = s7777;
				}
				else {
					str1 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr1 = s7777.substr(nbit, konec);
				}
			}
			if (i == 2) {

				if (nbit == 0) {
					str2 = s7777;
				}
				else {
					str2 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr2 = s7777.substr(nbit, konec);
				}
			}
			if (i == 3) {

				if (nbit == 0) {
					str3 = s7777;
				}
				else {
					str3 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr3 = s7777.substr(nbit, konec);
				}
			}
			if (i == 4) {

				if (nbit == 0) {
					str4 = s7777;
				}
				else {
					str4 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr4 = s7777.substr(nbit, konec);
				}
			}
			if (i == 5) {

				if (nbit == 0) {
					str5 = s7777;
				}
				else {
					str5 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr5 = s7777.substr(nbit, konec);
				}
			}
			if (i == 6) {

				if (nbit == 0) {
					str6 = s7777;
				}
				else {
					str6 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr6 = s7777.substr(nbit, konec);
				}
			}
			if (i == 7) {
				if (nbit == 0) {
					str7 = s7777;
				}
				else {
					str7 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr7 = s7777.substr(nbit, konec);
				}
			}
			if (i == 8) {
				if (nbit == 0) {
					str8 = s7777;
				}
				else {
					str8 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr8 = s7777.substr(nbit, konec);
				}
			}
			if (i == 9) {
				if (nbit == 0) {
					str9 = s7777;
				}
				else {
					str9 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr9 = s7777.substr(nbit, konec);
				}
			}
			if (i == 10) {
				if (nbit == 0) {
					str10 = s7777;
				}
				else {
					str10 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr10 = s7777.substr(nbit, konec);
				}
			}
			if (i == 11) {
				if (nbit == 0) {
					str11 = s7777;
				}
				else {
					str11 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr11 = s7777.substr(nbit, konec);
				}
			}
			if (i == 12) {
				if (nbit == 0) {
					str12 = s7777;
				}
				else {
					str12 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr12 = s7777.substr(nbit, konec);
				}
			}
			if (i == 13) {
				if (nbit == 0) {
					str13 = s7777;
				}
				else {
					str13 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr13 = s7777.substr(nbit, konec);
				}
			}
			if (i == 14) {
				if (nbit == 0) {
					str14 = s7777;
				}
				else {
					str14 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr14 = s7777.substr(nbit, konec);
				}
			}
			if (i == 15) {
				if (nbit == 0) {
					str15 = s7777;
				}
				else {
					str15 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr15 = s7777.substr(nbit, konec);
				}
			}
			if (i == 16) {
				if (nbit == 0) {
					str16 = s7777;
				}
				else {
					str16 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr16 = s7777.substr(nbit, konec);
				}
			}
			if (i == 17) {
				if (nbit == 0) {
					str17 = s7777;
				}
				else {
					str17 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr17 = s7777.substr(nbit, konec);
				}
			}
			if (i == 18) {
				if (nbit == 0) {
					str18 = s7777;
				}
				else {
					str18 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr18 = s7777.substr(nbit, konec);
				}
			}
			if (i == 19) {
				if (nbit == 0) {
					str19 = s7777;
				}
				else {
					str19 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr19 = s7777.substr(nbit, konec);
				}
			}
			if (i == 20) {
				if (nbit == 0) {
					str20 = s7777;
				}
				else {
					str20 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr20 = s7777.substr(nbit, konec);
				}
			}
			if (i == 21) {
				if (nbit == 0) {
					str21 = s7777;
				}
				else {
					str21 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr21 = s7777.substr(nbit, konec);
				}
			}
			if (i == 22) {
				if (nbit == 0) {
					str22 = s7777;
				}
				else {
					str22 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr22 = s7777.substr(nbit, konec);
				}
			}
			if (i == 23) {
				if (nbit == 0) {
					str23 = s7777;
				}
				else {
					str23 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr23 = s7777.substr(nbit, konec);
				}
			}
			if (i == 24) {
				if (nbit == 0) {
					str24 = s7777;
				}
				else {
					str24 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr24 = s7777.substr(nbit, konec);
				}
			}
			if (i == 25) {
				if (nbit == 0) {
					str25 = s7777;
				}
				else {
					str25 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr25 = s7777.substr(nbit, konec);
				}
			}
			if (i == 26) {
				if (nbit == 0) {
					str26 = s7777;
				}
				else {
					str26 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr26 = s7777.substr(nbit, konec);
				}
			}
			if (i == 27) {
				if (nbit == 0) {
					str27 = s7777;
				}
				else {
					str27 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr27 = s7777.substr(nbit, konec);
				}
			}
			if (i == 28) {
				if (nbit == 0) {
					str28 = s7777;
				}
				else {
					str28 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr28 = s7777.substr(nbit, konec);
				}
			}
			if (i == 29) {
				if (nbit == 0) {
					str29 = s7777;
				}
				else {
					str29 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr29 = s7777.substr(nbit, konec);
				}
			}
			if (i == 30) {
				if (nbit == 0) {
					str30 = s7777;
				}
				else {
					str30 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr30 = s7777.substr(nbit, konec);
				}
			}
			if (i == 31) {
				if (nbit == 0) {
					str31 = s7777;
				}
				else {
					str31 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr31 = s7777.substr(nbit, konec);
				}
			}
			if (i == 32) {
				if (nbit == 0) {
					str32 = s7777;
				}
				else {
					str32 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr32 = s7777.substr(nbit, konec);
				}
			}
			if (i == 33) {
				if (nbit == 0) {
					str33 = s7777;
				}
				else {
					str33 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr33 = s7777.substr(nbit, konec);
				}
			}
			if (i == 34) {
				if (nbit == 0) {
					str34 = s7777;
				}
				else {
					str34 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr34 = s7777.substr(nbit, konec);
				}
			}
			if (i == 35) {
				if (nbit == 0) {
					str35 = s7777;
				}
				else {
					str35 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr35 = s7777.substr(nbit, konec);
				}
			}
			if (i == 36) {
				if (nbit == 0) {
					str36 = s7777;
				}
				else {
					str36 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr36 = s7777.substr(nbit, konec);
				}
			}
			if (i == 37) {
				if (nbit == 0) {
					str37 = s7777;
				}
				else {
					str37 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr37 = s7777.substr(nbit, konec);
				}
			}
			if (i == 38) {
				if (nbit == 0) {
					str38 = s7777;
				}
				else {
					str38 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr38 = s7777.substr(nbit, konec);
				}
			}
			if (i == 39) {
				if (nbit == 0) {
					str39 = s7777;
				}
				else {
					str39 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr39 = s7777.substr(nbit, konec);
				}
			}
			if (i == 40) {
				if (nbit == 0) {
					str40 = s7777;
				}
				else {
					str40 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr40 = s7777.substr(nbit, konec);
				}
			}
			if (i == 41) {
				if (nbit == 0) {
					str41 = s7777;
				}
				else {
					str41 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr41 = s7777.substr(nbit, konec);
				}
			}
			if (i == 42) {
				if (nbit == 0) {
					str42 = s7777;
				}
				else {
					str42 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr42 = s7777.substr(nbit, konec);
				}
			}
			if (i == 43) {
				if (nbit == 0) {
					str43 = s7777;
				}
				else {
					str43 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr43 = s7777.substr(nbit, konec);
				}
			}
			if (i == 44) {
				if (nbit == 0) {
					str44 = s7777;
				}
				else {
					str44 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr44 = s7777.substr(nbit, konec);
				}
			}
			if (i == 45) {
				if (nbit == 0) {
					str45 = s7777;
				}
				else {
					str45 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr45 = s7777.substr(nbit, konec);
				}
			}
			if (i == 46) {
				if (nbit == 0) {
					str46 = s7777;
				}
				else {
					str46 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr46 = s7777.substr(nbit, konec);
				}
			}
			if (i == 47) {
				if (nbit == 0) {
					str47 = s7777;
				}
				else {
					str47 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr47 = s7777.substr(nbit, konec);
				}
			}
			if (i == 48) {
				if (nbit == 0) {
					str48 = s7777;
				}
				else {
					str48 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr48 = s7777.substr(nbit, konec);
				}
			}
			if (i == 49) {
				if (nbit == 0) {
					str49 = s7777;
				}
				else {
					str49 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr49 = s7777.substr(nbit, konec);
				}
			}
			if (i == 50) {
				if (nbit == 0) {
					str50 = s7777;
				}
				else {
					str50 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr50 = s7777.substr(nbit, konec);
				}
			}
			if (i == 51) {
				if (nbit == 0) {
					str51 = s7777;
				}
				else {
					str51 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr51 = s7777.substr(nbit, konec);
				}
			}
			if (i == 52) {
				if (nbit == 0) {
					str52 = s7777;
				}
				else {
					str52 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr52 = s7777.substr(nbit, konec);
				}
			}
			if (i == 53) {
				if (nbit == 0) {
					str53 = s7777;
				}
				else {
					str53 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr53 = s7777.substr(nbit, konec);
				}
			}
			if (i == 54) {
				if (nbit == 0) {
					str54 = s7777;
				}
				else {
					str54 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr54 = s7777.substr(nbit, konec);
				}
			}
			if (i == 55) {
				if (nbit == 0) {
					str55 = s7777;
				}
				else {
					str55 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr55 = s7777.substr(nbit, konec);
				}
			}
			if (i == 56) {
				if (nbit == 0) {
					str56 = s7777;
				}
				else {
					str56 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr56 = s7777.substr(nbit, konec);
				}
			}
			if (i == 57) {
				if (nbit == 0) {
					str57 = s7777;
				}
				else {
					str57 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr57 = s7777.substr(nbit, konec);
				}
			}
			if (i == 58) {
				if (nbit == 0) {
					str58 = s7777;
				}
				else {
					str58 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr58 = s7777.substr(nbit, konec);
				}
			}
			if (i == 59) {
				if (nbit == 0) {
					str59 = s7777;
				}
				else {
					str59 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr59 = s7777.substr(nbit, konec);
				}
			}
			if (i == 60) {
				if (nbit == 0) {
					str60 = s7777;
				}
				else {
					str60 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr60 = s7777.substr(nbit, konec);
				}
			}
			if (i == 61) {
				if (nbit == 0) {
					str61 = s7777;
				}
				else {
					str61 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr61 = s7777.substr(nbit, konec);
				}
			}
			if (i == 62) {
				if (nbit == 0) {
					str62 = s7777;
				}
				else {
					str62 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr62 = s7777.substr(nbit, konec);
				}
			}
			if (i == 63) {
				if (nbit == 0) {
					str63 = s7777;
				}
				else {
					str63 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr63 = s7777.substr(nbit, konec);
				}
			}
			if (i == 64) {
				if (nbit == 0) {
					str64 = s7777;
				}
				else {
					str64 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr64 = s7777.substr(nbit, konec);
				}
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 4) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search Passphrases. MAX -t 64\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-Passphrases.txt\n");
		if (nbit == 0 || nbit < 5) {
			printf("  Rotor        : DISABLED! Filter-replacement of 3 identical letters (AAA->AAB) Use -n 60 (every ~60 sek. or -n 5-600000)\n");
		}
		else {
			printf("  Rotor        : Activated filter-replacement of 3 identical letters (AAA->AAB) every ~%d seconds\n", nbit);
		}
		printf("  Letters      : (ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz )\n");

		ifstream file7777("Passphrases.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);
			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file Passphrases.txt line %d is empty!!! \n  1 core = 1 line with Passphrase! \n  %d cores = %d Passphrase in the Passphrases.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}

			if (s7777.length() < 3) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : Passphrase on line %d has the wrong length of %d letters!\n  Minimum 4 letters! \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {
				str0 = s7777;
				printf("  Passphrase1  : %s \n", str0.c_str());
			}
			if (i == nbit2 - 1) {
				printf("              ... \n");
				printf("  Passphrase%d  : %s \n", nbit2, s7777.c_str());
			}
			if (i == 1) {
				str1 = s7777;
			}
			if (i == 2) {
				str2 = s7777;
			}
			if (i == 3) {
				str3 = s7777;
			}
			if (i == 4) {
				str4 = s7777;
			}
			if (i == 5) {
				str5 = s7777;
			}
			if (i == 6) {
				str6 = s7777;
			}
			if (i == 7) {
				str7 = s7777;
			}
			if (i == 8) {
				str8 = s7777;
			}
			if (i == 9) {
				str9 = s7777;
			}
			if (i == 10) {
				str10 = s7777;
			}
			if (i == 11) {
				str11 = s7777;
			}
			if (i == 12) {
				str12 = s7777;
			}
			if (i == 13) {
				str13 = s7777;
			}
			if (i == 14) {
				str14 = s7777;
			}
			if (i == 15) {
				str15 = s7777;
			}
			if (i == 16) {
				str16 = s7777;
			}
			if (i == 17) {
				str17 = s7777;
			}
			if (i == 18) {
				str18 = s7777;
			}
			if (i == 19) {
				str19 = s7777;
			}
			if (i == 20) {
				str20 = s7777;
			}
			if (i == 21) {
				str21 = s7777;
			}
			if (i == 22) {
				str22 = s7777;
			}
			if (i == 23) {
				str23 = s7777;
			}
			if (i == 24) {
				str24 = s7777;
			}
			if (i == 25) {
				str25 = s7777;
			}
			if (i == 26) {
				str26 = s7777;
			}
			if (i == 27) {
				str27 = s7777;
			}
			if (i == 28) {
				str28 = s7777;
			}
			if (i == 29) {
				str29 = s7777;
			}
			if (i == 30) {
				str30 = s7777;
			}
			if (i == 31) {
				str31 = s7777;
			}
			if (i == 32) {
				str32 = s7777;
			}
			if (i == 33) {
				str33 = s7777;
			}
			if (i == 34) {
				str34 = s7777;
			}
			if (i == 35) {
				str35 = s7777;
			}
			if (i == 36) {
				str36 = s7777;
			}
			if (i == 37) {
				str37 = s7777;
			}
			if (i == 38) {
				str38 = s7777;
			}
			if (i == 39) {
				str39 = s7777;
			}
			if (i == 40) {
				str40 = s7777;
			}
			if (i == 41) {
				str41 = s7777;
			}
			if (i == 42) {
				str42 = s7777;
			}
			if (i == 43) {
				str43 = s7777;
			}
			if (i == 44) {
				str44 = s7777;
			}
			if (i == 45) {
				str45 = s7777;
			}
			if (i == 46) {
				str46 = s7777;
			}
			if (i == 47) {
				str47 = s7777;
			}
			if (i == 48) {
				str48 = s7777;
			}
			if (i == 49) {
				str49 = s7777;
			}
			if (i == 50) {
				str50 = s7777;
			}
			if (i == 51) {
				str51 = s7777;
			}
			if (i == 52) {
				str52 = s7777;
			}
			if (i == 53) {
				str53 = s7777;
			}
			if (i == 54) {
				str54 = s7777;
			}
			if (i == 55) {
				str55 = s7777;
			}
			if (i == 56) {
				str56 = s7777;
			}
			if (i == 57) {
				str57 = s7777;
			}
			if (i == 58) {
				str58 = s7777;
			}
			if (i == 59) {
				str59 = s7777;
			}
			if (i == 60) {
				str60 = s7777;
			}
			if (i == 61) {
				str61 = s7777;
			}
			if (i == 62) {
				str62 = s7777;
			}
			if (i == 63) {
				str63 = s7777;
			}
			if (i == 64) {
				str64 = s7777;
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 5) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search Passphrases. MAX -t 64\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-Passphrases.txt\n");
		if (nbit == 0 || nbit < 5) {
			printf("  Rotor        : DISABLED! Filter-replacement of 3 identical letters (AAA->AAB) Use -n 60 (every ~60 sek. or -n 5-600000)\n");
		}
		else {
			printf("  Rotor        : Activated filter-replacement of 3 identical letters (AAA->AAB) every ~%d seconds\n", nbit);
		}
		printf("  Letters      : (ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 )\n");

		ifstream file7777("Passphrases.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);
			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file Passphrases.txt line %d is empty!!! \n  1 core = 1 line with Passphrase! \n  %d cores = %d Passphrase in the Passphrases.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}

			if (s7777.length() < 3) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : Passphrase on line %d has the wrong length of %d letters!\n  Minimum 4 letters! \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {
				str0 = s7777;
				printf("  Passphrase1  : %s \n", str0.c_str());
			}
			if (i == nbit2 - 1) {
				printf("              ... \n");
				printf("  Passphrase%d  : %s \n", nbit2, s7777.c_str());
			}
			if (i == 1) {
				str1 = s7777;
			}
			if (i == 2) {
				str2 = s7777;
			}
			if (i == 3) {
				str3 = s7777;
			}
			if (i == 4) {
				str4 = s7777;
			}
			if (i == 5) {
				str5 = s7777;
			}
			if (i == 6) {
				str6 = s7777;
			}
			if (i == 7) {
				str7 = s7777;
			}
			if (i == 8) {
				str8 = s7777;
			}
			if (i == 9) {
				str9 = s7777;
			}
			if (i == 10) {
				str10 = s7777;
			}
			if (i == 11) {
				str11 = s7777;
			}
			if (i == 12) {
				str12 = s7777;
			}
			if (i == 13) {
				str13 = s7777;
			}
			if (i == 14) {
				str14 = s7777;
			}
			if (i == 15) {
				str15 = s7777;
			}
			if (i == 16) {
				str16 = s7777;
			}
			if (i == 17) {
				str17 = s7777;
			}
			if (i == 18) {
				str18 = s7777;
			}
			if (i == 19) {
				str19 = s7777;
			}
			if (i == 20) {
				str20 = s7777;
			}
			if (i == 21) {
				str21 = s7777;
			}
			if (i == 22) {
				str22 = s7777;
			}
			if (i == 23) {
				str23 = s7777;
			}
			if (i == 24) {
				str24 = s7777;
			}
			if (i == 25) {
				str25 = s7777;
			}
			if (i == 26) {
				str26 = s7777;
			}
			if (i == 27) {
				str27 = s7777;
			}
			if (i == 28) {
				str28 = s7777;
			}
			if (i == 29) {
				str29 = s7777;
			}
			if (i == 30) {
				str30 = s7777;
			}
			if (i == 31) {
				str31 = s7777;
			}
			if (i == 32) {
				str32 = s7777;
			}
			if (i == 33) {
				str33 = s7777;
			}
			if (i == 34) {
				str34 = s7777;
			}
			if (i == 35) {
				str35 = s7777;
			}
			if (i == 36) {
				str36 = s7777;
			}
			if (i == 37) {
				str37 = s7777;
			}
			if (i == 38) {
				str38 = s7777;
			}
			if (i == 39) {
				str39 = s7777;
			}
			if (i == 40) {
				str40 = s7777;
			}
			if (i == 41) {
				str41 = s7777;
			}
			if (i == 42) {
				str42 = s7777;
			}
			if (i == 43) {
				str43 = s7777;
			}
			if (i == 44) {
				str44 = s7777;
			}
			if (i == 45) {
				str45 = s7777;
			}
			if (i == 46) {
				str46 = s7777;
			}
			if (i == 47) {
				str47 = s7777;
			}
			if (i == 48) {
				str48 = s7777;
			}
			if (i == 49) {
				str49 = s7777;
			}
			if (i == 50) {
				str50 = s7777;
			}
			if (i == 51) {
				str51 = s7777;
			}
			if (i == 52) {
				str52 = s7777;
			}
			if (i == 53) {
				str53 = s7777;
			}
			if (i == 54) {
				str54 = s7777;
			}
			if (i == 55) {
				str55 = s7777;
			}
			if (i == 56) {
				str56 = s7777;
			}
			if (i == 57) {
				str57 = s7777;
			}
			if (i == 58) {
				str58 = s7777;
			}
			if (i == 59) {
				str59 = s7777;
			}
			if (i == 60) {
				str60 = s7777;
			}
			if (i == 61) {
				str61 = s7777;
			}
			if (i == 62) {
				str62 = s7777;
			}
			if (i == 63) {
				str63 = s7777;
			}
			if (i == 64) {
				str64 = s7777;
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 6) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search Passphrases. MAX -t 64\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-Passphrases.txt\n");
		if (nbit == 0 || nbit < 5) {
			printf("  Rotor        : DISABLED! Filter-replacement of 3 identical letters (AAA->AAB) Use -n 60 (every ~60 sek. or -n 5-600000)\n");
		}
		else {
			printf("  Rotor        : Activated filter-replacement of 3 identical letters (AAA->AAB) every ~%d seconds\n", nbit);
		}
		printf("  Letters      : (ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[]^_`{|}~  )\n");

		ifstream file7777("Passphrases.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);
			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file Passphrases.txt line %d is empty!!! \n  1 core = 1 line with Passphrase! \n  %d cores = %d Passphrase in the Passphrases.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}

			if (s7777.length() < 3) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : Passphrase on line %d has the wrong length of %d letters!\n  Minimum 4 letters! \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {
				str0 = s7777;
				printf("  Passphrase1  : %s \n", str0.c_str());
			}
			if (i == nbit2 - 1) {
				printf("              ... \n");
				printf("  Passphrase%d  : %s \n", nbit2, s7777.c_str());
			}
			if (i == 1) {
				str1 = s7777;
			}
			if (i == 2) {
				str2 = s7777;
			}
			if (i == 3) {
				str3 = s7777;
			}
			if (i == 4) {
				str4 = s7777;
			}
			if (i == 5) {
				str5 = s7777;
			}
			if (i == 6) {
				str6 = s7777;
			}
			if (i == 7) {
				str7 = s7777;
			}
			if (i == 8) {
				str8 = s7777;
			}
			if (i == 9) {
				str9 = s7777;
			}
			if (i == 10) {
				str10 = s7777;
			}
			if (i == 11) {
				str11 = s7777;
			}
			if (i == 12) {
				str12 = s7777;
			}
			if (i == 13) {
				str13 = s7777;
			}
			if (i == 14) {
				str14 = s7777;
			}
			if (i == 15) {
				str15 = s7777;
			}
			if (i == 16) {
				str16 = s7777;
			}
			if (i == 17) {
				str17 = s7777;
			}
			if (i == 18) {
				str18 = s7777;
			}
			if (i == 19) {
				str19 = s7777;
			}
			if (i == 20) {
				str20 = s7777;
			}
			if (i == 21) {
				str21 = s7777;
			}
			if (i == 22) {
				str22 = s7777;
			}
			if (i == 23) {
				str23 = s7777;
			}
			if (i == 24) {
				str24 = s7777;
			}
			if (i == 25) {
				str25 = s7777;
			}
			if (i == 26) {
				str26 = s7777;
			}
			if (i == 27) {
				str27 = s7777;
			}
			if (i == 28) {
				str28 = s7777;
			}
			if (i == 29) {
				str29 = s7777;
			}
			if (i == 30) {
				str30 = s7777;
			}
			if (i == 31) {
				str31 = s7777;
			}
			if (i == 32) {
				str32 = s7777;
			}
			if (i == 33) {
				str33 = s7777;
			}
			if (i == 34) {
				str34 = s7777;
			}
			if (i == 35) {
				str35 = s7777;
			}
			if (i == 36) {
				str36 = s7777;
			}
			if (i == 37) {
				str37 = s7777;
			}
			if (i == 38) {
				str38 = s7777;
			}
			if (i == 39) {
				str39 = s7777;
			}
			if (i == 40) {
				str40 = s7777;
			}
			if (i == 41) {
				str41 = s7777;
			}
			if (i == 42) {
				str42 = s7777;
			}
			if (i == 43) {
				str43 = s7777;
			}
			if (i == 44) {
				str44 = s7777;
			}
			if (i == 45) {
				str45 = s7777;
			}
			if (i == 46) {
				str46 = s7777;
			}
			if (i == 47) {
				str47 = s7777;
			}
			if (i == 48) {
				str48 = s7777;
			}
			if (i == 49) {
				str49 = s7777;
			}
			if (i == 50) {
				str50 = s7777;
			}
			if (i == 51) {
				str51 = s7777;
			}
			if (i == 52) {
				str52 = s7777;
			}
			if (i == 53) {
				str53 = s7777;
			}
			if (i == 54) {
				str54 = s7777;
			}
			if (i == 55) {
				str55 = s7777;
			}
			if (i == 56) {
				str56 = s7777;
			}
			if (i == 57) {
				str57 = s7777;
			}
			if (i == 58) {
				str58 = s7777;
			}
			if (i == 59) {
				str59 = s7777;
			}
			if (i == 60) {
				str60 = s7777;
			}
			if (i == 61) {
				str61 = s7777;
			}
			if (i == 62) {
				str62 = s7777;
			}
			if (i == 63) {
				str63 = s7777;
			}
			if (i == 64) {
				str64 = s7777;
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 7) {
		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search for WIF values. MAX -t 64, 1 core = 1 line\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-WIF.txt\n");
		ifstream file7777("WIF.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);

			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file WIF.txt line %d is empty!!! \n  1 core = 1 line with WIF private keys L,K,5! \n  %d cores = %d WIF private keys in the WIF.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}
			if (s7777[0] == 'K' || s7777[0] == 'L' || s7777[0] == '5') {

			}
			else {
				printf("\n  Rotor        : WIF private key starts with L,K,5 check file WIF.txt \n  This is %s NOT a WIF!\n  Check in the text file WIF.txt line %d  \n\n", s7777.c_str(), i + 1);
				exit(1);
			}
			if (s7777.length() > 52 || s7777.length() < 51) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : WIF private key on line %d has the wrong length of %d letters!\n  Uncompressed WIF 5.. (51 letters) \n  Compressed WIF L..,K.. (52 letters) \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {

				if (nbit == 0) {
					str0 = s7777;
					printf("  Start WIF(1) : %s \n", str0.c_str());
				}
				else {
					str0 = s7777.substr(0, nbit);
					int konec = s7777.length();
					int shte = konec - nbit;
					kstr0 = s7777.substr(nbit, konec);
					printf("  Rotor        : Movable part wif (%d) + fixed part (%d) \n", nbit, shte);
					printf("  Start WIF(1) : %s+[%s]\n", str0.c_str(), kstr0.c_str());
				}

			}
			if (i == nbit2 - 1) {


				printf("              ... \n");
				printf("  Start WIF(%d) : %s \n", nbit2, s7777.c_str());

			}

			if (i == 1) {

				if (nbit == 0) {
					str1 = s7777;
				}
				else {
					str1 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr1 = s7777.substr(nbit, konec);
				}
			}
			if (i == 2) {

				if (nbit == 0) {
					str2 = s7777;
				}
				else {
					str2 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr2 = s7777.substr(nbit, konec);
				}
			}
			if (i == 3) {

				if (nbit == 0) {
					str3 = s7777;
				}
				else {
					str3 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr3 = s7777.substr(nbit, konec);
				}
			}
			if (i == 4) {

				if (nbit == 0) {
					str4 = s7777;
				}
				else {
					str4 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr4 = s7777.substr(nbit, konec);
				}
			}
			if (i == 5) {

				if (nbit == 0) {
					str5 = s7777;
				}
				else {
					str5 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr5 = s7777.substr(nbit, konec);
				}
			}
			if (i == 6) {

				if (nbit == 0) {
					str6 = s7777;
				}
				else {
					str6 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr6 = s7777.substr(nbit, konec);
				}
			}
			if (i == 7) {
				if (nbit == 0) {
					str7 = s7777;
				}
				else {
					str7 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr7 = s7777.substr(nbit, konec);
				}
			}
			if (i == 8) {
				if (nbit == 0) {
					str8 = s7777;
				}
				else {
					str8 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr8 = s7777.substr(nbit, konec);
				}
			}
			if (i == 9) {
				if (nbit == 0) {
					str9 = s7777;
				}
				else {
					str9 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr9 = s7777.substr(nbit, konec);
				}
			}
			if (i == 10) {
				if (nbit == 0) {
					str10 = s7777;
				}
				else {
					str10 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr10 = s7777.substr(nbit, konec);
				}
			}
			if (i == 11) {
				if (nbit == 0) {
					str11 = s7777;
				}
				else {
					str11 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr11 = s7777.substr(nbit, konec);
				}
			}
			if (i == 12) {
				if (nbit == 0) {
					str12 = s7777;
				}
				else {
					str12 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr12 = s7777.substr(nbit, konec);
				}
			}
			if (i == 13) {
				if (nbit == 0) {
					str13 = s7777;
				}
				else {
					str13 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr13 = s7777.substr(nbit, konec);
				}
			}
			if (i == 14) {
				if (nbit == 0) {
					str14 = s7777;
				}
				else {
					str14 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr14 = s7777.substr(nbit, konec);
				}
			}
			if (i == 15) {
				if (nbit == 0) {
					str15 = s7777;
				}
				else {
					str15 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr15 = s7777.substr(nbit, konec);
				}
			}
			if (i == 16) {
				if (nbit == 0) {
					str16 = s7777;
				}
				else {
					str16 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr16 = s7777.substr(nbit, konec);
				}
			}
			if (i == 17) {
				if (nbit == 0) {
					str17 = s7777;
				}
				else {
					str17 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr17 = s7777.substr(nbit, konec);
				}
			}
			if (i == 18) {
				if (nbit == 0) {
					str18 = s7777;
				}
				else {
					str18 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr18 = s7777.substr(nbit, konec);
				}
			}
			if (i == 19) {
				if (nbit == 0) {
					str19 = s7777;
				}
				else {
					str19 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr19 = s7777.substr(nbit, konec);
				}
			}
			if (i == 20) {
				if (nbit == 0) {
					str20 = s7777;
				}
				else {
					str20 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr20 = s7777.substr(nbit, konec);
				}
			}
			if (i == 21) {
				if (nbit == 0) {
					str21 = s7777;
				}
				else {
					str21 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr21 = s7777.substr(nbit, konec);
				}
			}
			if (i == 22) {
				if (nbit == 0) {
					str22 = s7777;
				}
				else {
					str22 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr22 = s7777.substr(nbit, konec);
				}
			}
			if (i == 23) {
				if (nbit == 0) {
					str23 = s7777;
				}
				else {
					str23 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr23 = s7777.substr(nbit, konec);
				}
			}
			if (i == 24) {
				if (nbit == 0) {
					str24 = s7777;
				}
				else {
					str24 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr24 = s7777.substr(nbit, konec);
				}
			}
			if (i == 25) {
				if (nbit == 0) {
					str25 = s7777;
				}
				else {
					str25 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr25 = s7777.substr(nbit, konec);
				}
			}
			if (i == 26) {
				if (nbit == 0) {
					str26 = s7777;
				}
				else {
					str26 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr26 = s7777.substr(nbit, konec);
				}
			}
			if (i == 27) {
				if (nbit == 0) {
					str27 = s7777;
				}
				else {
					str27 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr27 = s7777.substr(nbit, konec);
				}
			}
			if (i == 28) {
				if (nbit == 0) {
					str28 = s7777;
				}
				else {
					str28 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr28 = s7777.substr(nbit, konec);
				}
			}
			if (i == 29) {
				if (nbit == 0) {
					str29 = s7777;
				}
				else {
					str29 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr29 = s7777.substr(nbit, konec);
				}
			}
			if (i == 30) {
				if (nbit == 0) {
					str30 = s7777;
				}
				else {
					str30 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr30 = s7777.substr(nbit, konec);
				}
			}
			if (i == 31) {
				if (nbit == 0) {
					str31 = s7777;
				}
				else {
					str31 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr31 = s7777.substr(nbit, konec);
				}
			}
			if (i == 32) {
				if (nbit == 0) {
					str32 = s7777;
				}
				else {
					str32 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr32 = s7777.substr(nbit, konec);
				}
			}
			if (i == 33) {
				if (nbit == 0) {
					str33 = s7777;
				}
				else {
					str33 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr33 = s7777.substr(nbit, konec);
				}
			}
			if (i == 34) {
				if (nbit == 0) {
					str34 = s7777;
				}
				else {
					str34 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr34 = s7777.substr(nbit, konec);
				}
			}
			if (i == 35) {
				if (nbit == 0) {
					str35 = s7777;
				}
				else {
					str35 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr35 = s7777.substr(nbit, konec);
				}
			}
			if (i == 36) {
				if (nbit == 0) {
					str36 = s7777;
				}
				else {
					str36 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr36 = s7777.substr(nbit, konec);
				}
			}
			if (i == 37) {
				if (nbit == 0) {
					str37 = s7777;
				}
				else {
					str37 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr37 = s7777.substr(nbit, konec);
				}
			}
			if (i == 38) {
				if (nbit == 0) {
					str38 = s7777;
				}
				else {
					str38 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr38 = s7777.substr(nbit, konec);
				}
			}
			if (i == 39) {
				if (nbit == 0) {
					str39 = s7777;
				}
				else {
					str39 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr39 = s7777.substr(nbit, konec);
				}
			}
			if (i == 40) {
				if (nbit == 0) {
					str40 = s7777;
				}
				else {
					str40 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr40 = s7777.substr(nbit, konec);
				}
			}
			if (i == 41) {
				if (nbit == 0) {
					str41 = s7777;
				}
				else {
					str41 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr41 = s7777.substr(nbit, konec);
				}
			}
			if (i == 42) {
				if (nbit == 0) {
					str42 = s7777;
				}
				else {
					str42 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr42 = s7777.substr(nbit, konec);
				}
			}
			if (i == 43) {
				if (nbit == 0) {
					str43 = s7777;
				}
				else {
					str43 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr43 = s7777.substr(nbit, konec);
				}
			}
			if (i == 44) {
				if (nbit == 0) {
					str44 = s7777;
				}
				else {
					str44 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr44 = s7777.substr(nbit, konec);
				}
			}
			if (i == 45) {
				if (nbit == 0) {
					str45 = s7777;
				}
				else {
					str45 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr45 = s7777.substr(nbit, konec);
				}
			}
			if (i == 46) {
				if (nbit == 0) {
					str46 = s7777;
				}
				else {
					str46 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr46 = s7777.substr(nbit, konec);
				}
			}
			if (i == 47) {
				if (nbit == 0) {
					str47 = s7777;
				}
				else {
					str47 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr47 = s7777.substr(nbit, konec);
				}
			}
			if (i == 48) {
				if (nbit == 0) {
					str48 = s7777;
				}
				else {
					str48 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr48 = s7777.substr(nbit, konec);
				}
			}
			if (i == 49) {
				if (nbit == 0) {
					str49 = s7777;
				}
				else {
					str49 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr49 = s7777.substr(nbit, konec);
				}
			}
			if (i == 50) {
				if (nbit == 0) {
					str50 = s7777;
				}
				else {
					str50 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr50 = s7777.substr(nbit, konec);
				}
			}
			if (i == 51) {
				if (nbit == 0) {
					str51 = s7777;
				}
				else {
					str51 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr51 = s7777.substr(nbit, konec);
				}
			}
			if (i == 52) {
				if (nbit == 0) {
					str52 = s7777;
				}
				else {
					str52 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr52 = s7777.substr(nbit, konec);
				}
			}
			if (i == 53) {
				if (nbit == 0) {
					str53 = s7777;
				}
				else {
					str53 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr53 = s7777.substr(nbit, konec);
				}
			}
			if (i == 54) {
				if (nbit == 0) {
					str54 = s7777;
				}
				else {
					str54 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr54 = s7777.substr(nbit, konec);
				}
			}
			if (i == 55) {
				if (nbit == 0) {
					str55 = s7777;
				}
				else {
					str55 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr55 = s7777.substr(nbit, konec);
				}
			}
			if (i == 56) {
				if (nbit == 0) {
					str56 = s7777;
				}
				else {
					str56 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr56 = s7777.substr(nbit, konec);
				}
			}
			if (i == 57) {
				if (nbit == 0) {
					str57 = s7777;
				}
				else {
					str57 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr57 = s7777.substr(nbit, konec);
				}
			}
			if (i == 58) {
				if (nbit == 0) {
					str58 = s7777;
				}
				else {
					str58 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr58 = s7777.substr(nbit, konec);
				}
			}
			if (i == 59) {
				if (nbit == 0) {
					str59 = s7777;
				}
				else {
					str59 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr59 = s7777.substr(nbit, konec);
				}
			}
			if (i == 60) {
				if (nbit == 0) {
					str60 = s7777;
				}
				else {
					str60 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr60 = s7777.substr(nbit, konec);
				}
			}
			if (i == 61) {
				if (nbit == 0) {
					str61 = s7777;
				}
				else {
					str61 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr61 = s7777.substr(nbit, konec);
				}
			}
			if (i == 62) {
				if (nbit == 0) {
					str62 = s7777;
				}
				else {
					str62 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr62 = s7777.substr(nbit, konec);
				}
			}
			if (i == 63) {
				if (nbit == 0) {
					str63 = s7777;
				}
				else {
					str63 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr63 = s7777.substr(nbit, konec);
				}
			}
			if (i == 64) {
				if (nbit == 0) {
					str64 = s7777;
				}
				else {
					str64 = s7777.substr(0, nbit);
					int konec = s7777.length();
					kstr64 = s7777.substr(nbit, konec);
				}
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 8) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search Minikeys. MAX -t 64\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEW-Minikeys.txt\n");
		printf("  Letters      : Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)\n");

		ifstream file7777("Minikeys.txt");
		string s7777;
		string initial;
		for (int i = 0; i < nbit2; i++) {
			getline(file7777, s7777);

			if (s7777[0] == 'S') {

			}
			else {
				printf("\n  Rotor        : Minikeys start with the letter S... check file Minikeys.txt \n  This is %s NOT a Minikeys!\n  Check in the text file Minikeys.txt line %d  \n\n", s7777.c_str(), i + 1);
				exit(1);

			}

			if (s7777.length() > 30 || s7777.length() < 22) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : Minikey on line %d has the wrong length of %d letters!\n  Use Minikey S... (22 letters) \n  Minikey S... (30 letters) \n\n", i + 1, oshibka);
				exit(1);
			}
			if (s7777 == "") {
				printf("\n  Rotor        : Check the text file Minikeys.txt line %d is empty!!! \n  1 core = 1 line with Minikeys! \n  %d cores = %d Minikeys in the Minikeys.txt file\n\n", i + 1, nbit2, nbit2);
				exit(1);

			}

			if (s7777.length() < 3) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : Minikey on line %d has the wrong length of %d letters!\n  Minimum 4 letters! \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {
				str0 = s7777;
				printf("  Minikey1     : %s \n", str0.c_str());
			}
			if (i == nbit2 - 1) {
				printf("              ... \n");
				printf("  Minikey%d     : %s \n", nbit2, s7777.c_str());
			}
			if (i == 1) {
				str1 = s7777;
			}
			if (i == 2) {
				str2 = s7777;
			}
			if (i == 3) {
				str3 = s7777;
			}
			if (i == 4) {
				str4 = s7777;
			}
			if (i == 5) {
				str5 = s7777;
			}
			if (i == 6) {
				str6 = s7777;
			}
			if (i == 7) {
				str7 = s7777;
			}
			if (i == 8) {
				str8 = s7777;
			}
			if (i == 9) {
				str9 = s7777;
			}
			if (i == 10) {
				str10 = s7777;
			}
			if (i == 11) {
				str11 = s7777;
			}
			if (i == 12) {
				str12 = s7777;
			}
			if (i == 13) {
				str13 = s7777;
			}
			if (i == 14) {
				str14 = s7777;
			}
			if (i == 15) {
				str15 = s7777;
			}
			if (i == 16) {
				str16 = s7777;
			}
			if (i == 17) {
				str17 = s7777;
			}
			if (i == 18) {
				str18 = s7777;
			}
			if (i == 19) {
				str19 = s7777;
			}
			if (i == 20) {
				str20 = s7777;
			}
			if (i == 21) {
				str21 = s7777;
			}
			if (i == 22) {
				str22 = s7777;
			}
			if (i == 23) {
				str23 = s7777;
			}
			if (i == 24) {
				str24 = s7777;
			}
			if (i == 25) {
				str25 = s7777;
			}
			if (i == 26) {
				str26 = s7777;
			}
			if (i == 27) {
				str27 = s7777;
			}
			if (i == 28) {
				str28 = s7777;
			}
			if (i == 29) {
				str29 = s7777;
			}
			if (i == 30) {
				str30 = s7777;
			}
			if (i == 31) {
				str31 = s7777;
			}
			if (i == 32) {
				str32 = s7777;
			}
			if (i == 33) {
				str33 = s7777;
			}
			if (i == 34) {
				str34 = s7777;
			}
			if (i == 35) {
				str35 = s7777;
			}
			if (i == 36) {
				str36 = s7777;
			}
			if (i == 37) {
				str37 = s7777;
			}
			if (i == 38) {
				str38 = s7777;
			}
			if (i == 39) {
				str39 = s7777;
			}
			if (i == 40) {
				str40 = s7777;
			}
			if (i == 41) {
				str41 = s7777;
			}
			if (i == 42) {
				str42 = s7777;
			}
			if (i == 43) {
				str43 = s7777;
			}
			if (i == 44) {
				str44 = s7777;
			}
			if (i == 45) {
				str45 = s7777;
			}
			if (i == 46) {
				str46 = s7777;
			}
			if (i == 47) {
				str47 = s7777;
			}
			if (i == 48) {
				str48 = s7777;
			}
			if (i == 49) {
				str49 = s7777;
			}
			if (i == 50) {
				str50 = s7777;
			}
			if (i == 51) {
				str51 = s7777;
			}
			if (i == 52) {
				str52 = s7777;
			}
			if (i == 53) {
				str53 = s7777;
			}
			if (i == 54) {
				str54 = s7777;
			}
			if (i == 55) {
				str55 = s7777;
			}
			if (i == 56) {
				str56 = s7777;
			}
			if (i == 57) {
				str57 = s7777;
			}
			if (i == 58) {
				str58 = s7777;
			}
			if (i == 59) {
				str59 = s7777;
			}
			if (i == 60) {
				str60 = s7777;
			}
			if (i == 61) {
				str61 = s7777;
			}
			if (i == 62) {
				str62 = s7777;
			}
			if (i == 63) {
				str63 = s7777;
			}
			if (i == 64) {
				str64 = s7777;
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 9) {
		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Paralleland sequential search for WIF 65536 values\n");
		printf("  Rotor        : Save checkpoints every 5 minutes in NEXT-WIF.txt\n");
		ifstream file7777("WIF.txt");
		string s7777;
		string initial;
		for (int i = 0; i < 65536; i++) {
			getline(file7777, s7777);

			if (s7777[0] == 'K' || s7777[0] == 'L' || s7777[0] == '5') {

			}
			else {
				printf("\n  Rotor        : WIF private key starts with L,K,5 check file WIF.txt \n  This is %s NOT a WIF!\n  Check in the text file WIF.txt line %d  \n\n", s7777.c_str(), i + 1);
				exit(1);
			}
			if (s7777.length() > 52 || s7777.length() < 51) {
				int oshibka = s7777.length();
				printf("\n  Rotor        : WIF private key on line %d has the wrong length of %d letters!\n  Uncompressed WIF 5.. (51 letters) \n  Compressed WIF L..,K.. (52 letters) \n\n", i + 1, oshibka);
				exit(1);
			}

			if (i == 0) {
				str0 = s7777;
				printf("  Start WIF(1) : %s \n", str0.c_str());
			}

			if (i == 65535) {
				printf("           ... \n");
				printf("  Start WIF(%d) : %s \n", i, s7777.c_str());
			}
		}
		file7777.close();
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}

	if (rekey == 10) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Random search Minikeys 22 litters. Ex. Sxxxxxxxxxxxxxxxxxxxxx\n");
		printf("  Letters      : Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)\n");
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey == 11) {

		printf("\n  Mode         : %.0f \n", (double)rekey);
		printf("  Rotor        : Random search Minikeys 30 litters. Ex. Sxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
		printf("  Letters      : Base58 (ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789)\n");
		printf("  Site         : https://github.com/phrutis/Fialka \n  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}
	if (rekey > 11) {
		printf("\n  More modes in development! Visit to https://github.com/phrutis/Fialka \n\n");
		exit(1);
	
	}
}

// ----------------------------------------------------------------------------

Fialka::~Fialka()
{
	delete secp;
	if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
		delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void Fialka::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{

#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("  Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");
	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n  =================================================================================\n");
	fprintf(stdout, "  PubAddress: %s\n", addr.c_str());

	if (coinType == COIN_BTC) {
		fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
		fprintf(stdout, "  Priv (WIF): p2pkh:%s\n", pAddr.c_str());
	}

	fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());
	fprintf(stdout, "  Priv (HEX): %s\n", pAddrHex.c_str());

	fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(stdout, "  PubK (HEX): %s\n", pubKey.c_str());

	fprintf(f, "=================================================================================\n");
	fprintf(stdout, "  =================================================================================\n");

	if (needToClose)
		fclose(f);
#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------

bool Fialka::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddress(mode, p);
	if (chkAddr != addr) {
		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddress(mode, p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK : %s\n", k2.GetBase16().c_str());
			printf("  Addr : %s\n", addr.c_str());
			printf("  PubX : %s\n", px.c_str());
			printf("  PivK : %s\n", k.GetBase16().c_str());
			printf("  Check: %s\n", chkAddr.c_str());
			printf("  PubX : %s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

bool Fialka::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddressETH(p);
	if (chkAddr != addr) {
		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddressETH(p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK :%s\n", k2.GetBase16().c_str());
			printf("  Addr :%s\n", addr.c_str());
			printf("  PubX :%s\n", px.c_str());
			printf("  PivK :%s\n", k.GetBase16().c_str());
			printf("  Check:%s\n", chkAddr.c_str());
			printf("  PubX :%s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, k.GetBase16()/*secp->GetPrivAddressETH(k)*/, k.GetBase16(), secp->GetPublicKeyHexETH(p));
	return true;
}

bool Fialka::checkPrivKeyX(Int& key, int32_t incr, bool mode)
{
	Int k(&key);
	k.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k);
	std::string addr = secp->GetAddress(mode, p);
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
{
#else
void* _FindKeyCPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void* _FindKeyGPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void Fialka::checkMultiAddresses(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkMultiAddressesETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddressETH(h0);
		if (checkPrivKeyETH(addr, key, i)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkSingleAddress(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkSingleAddressETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddressETH(h0);
		if (checkPrivKeyETH(addr, key, i)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkMultiXPoints(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32];

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (CheckBloomBinary(h0, 32) > 0) {
		if (checkPrivKeyX(key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkSingleXPoint(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32];

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (MatchXPoint((uint32_t*)h0)) {
		if (checkPrivKeyX(key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::checkMultiAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i + 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h1);
		if (checkPrivKey(addr, key, i + 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h2);
		if (checkPrivKey(addr, key, i + 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h3);
		if (checkPrivKey(addr, key, i + 3, compressed)) {
			nbFoundKey++;
		}
	}

}

// ----------------------------------------------------------------------------

void Fialka::checkSingleAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i + 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h1)) {
		std::string addr = secp->GetAddress(compressed, h1);
		if (checkPrivKey(addr, key, i + 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h2)) {
		std::string addr = secp->GetAddress(compressed, h2);
		if (checkPrivKey(addr, key, i + 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h3)) {
		std::string addr = secp->GetAddress(compressed, h3);
		if (checkPrivKey(addr, key, i + 3, compressed)) {
			nbFoundKey++;
		}
	}

}

static string const digits = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789";
static string const digits2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ";
static string const digits3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ";
static string const digits4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[]^_`{|}~ ";

string increment(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits.find(value.at(i));
		v += carry;
		carry = v >= digits.size();
		v = carry ? 0 : v;
		result.push_back(digits.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits(char a, char b) {
	int va = digits.find(a);
	int vb = digits.find(b);
	return va < vb;
}

bool compare(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits);
}

string increment2(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits2.find(value.at(i));
		v += carry;
		carry = v >= digits2.size();
		v = carry ? 0 : v;
		result.push_back(digits2.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits2(char a, char b) {
	int va = digits2.find(a);
	int vb = digits2.find(b);
	return va < vb;
}

bool compare2(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits2);
}

string increment3(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits3.find(value.at(i));
		v += carry;
		carry = v >= digits3.size();
		v = carry ? 0 : v;
		result.push_back(digits3.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits3(char a, char b) {
	int va = digits3.find(a);
	int vb = digits3.find(b);
	return va < vb;
}

bool compare3(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits3);
}

string increment4(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits4.find(value.at(i));
		v += carry;
		carry = v >= digits4.size();
		v = carry ? 0 : v;
		result.push_back(digits4.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits4(char a, char b) {
	int va = digits4.find(a);
	int vb = digits4.find(b);
	return va < vb;
}

bool compare4(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits4);
}

void Fialka::getCPUStartingKey(Int & tRangeStart, Int & tRangeEnd, Int & key, Point & startP)
{

}

void Fialka::FindKeyCPU(TH_PARAM * ph)
{
	if (rekey == 1) {

		int err = 0;
		int thId = ph->threadId;
		
		counters[thId] = 0;

		Int  key;
		Point startP;

		ph->hasStarted = true;
		ph->rKeyRequest = false;
		ifstream file77(seed);

		if (thId == 0) {
			string s77;
			int bt = 0;
			while (getline(file77, s77)) {
				bt++;
				if (bt < kusok + kusok) {
					if (regex_search(s77, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = s77;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);

						}
						if (zez == "Passphrases") {

							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						input1 = input;
						input2 = key;
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							}
						}
						counters[thId] += 1;
						if (bt >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 1) {
			string s78;
			int bt1 = 0;
			while (getline(file77, s78)) {
				bt1++;
				if (bt1 > kusok) {
					if (regex_search(s78, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = s78;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);

						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt1 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 2) {
			string s79;
			int bt2 = 0;
			while (getline(file77, s79)) {
				bt2++;
				if (bt2 > kusok + kusok) {
					if (regex_search(s79, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = s79;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt2 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 3) {
			string sk8;
			int bt3 = 0;
			while (getline(file77, sk8)) {
				bt3++;
				if (bt3 > kusok * 3) {
					if (regex_search(sk8, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = sk8;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt3 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 4) {
			string sk9;
			int bt4 = 0;
			while (getline(file77, sk9)) {
				bt4++;
				if (bt4 > kusok * 4) {
					if (regex_search(sk9, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = sk9;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt4 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 5) {
			string sr7;
			int bt5 = 0;
			while (getline(file77, sr7)) {
				bt5++;
				if (bt5 > kusok * 5) {
					if (regex_search(sr7, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = sr7;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt5 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 6) {
			string tr6;
			int bt6 = 0;
			while (getline(file77, tr6)) {
				bt6++;
				if (bt6 > kusok * 6) {
					if (regex_search(tr6, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = tr6;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);

						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt6 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 7) {
			string tr7;
			int bt7 = 0;
			while (getline(file77, tr7)) {
				bt7++;
				if (bt7 > kusok * 7) {
					if (regex_search(tr7, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = tr7;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt7 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 8) {
			string tr8;
			int bt8 = 0;
			while (getline(file77, tr8)) {
				bt8++;
				if (bt8 > kusok * 8) {
					if (regex_search(tr8, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = tr8;
						if (zez == "keys") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt8 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 9) {
			string tr9;
			int bt9 = 0;
			while (getline(file77, tr9)) {
				bt9++;
				if (bt9 > kusok * 9) {
					if (regex_search(tr9, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = tr9;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (bt9 >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		if (thId == 10) {
			string gtr9;
			int btt = 0;
			while (getline(file77, gtr9)) {
				btt++;
				if (btt > kusok * 10) {
					if (regex_search(gtr9, regex("[^À-ßà-ÿA-Za-z0-9¸¨üÚÜú `~!@#$%&*()-_=+{}|;:'<>,./?\r\n]"))) {
						counters2 += 1;
					}
					else {
						string input = gtr9;
						if (zez == "HEX") {
							char* cstr = &input[0];
							key.SetBase16(cstr);
						}
						if (zez == "WIF") {
							bool isComp;
							key = secp->DecodePrivateKey((char*)input.c_str(), &isComp);
						}
						if (zez == "Passphrases") {
							string nos = sha256(input);
							char* cstr = &nos[0];
							key.SetBase16(cstr);
						}
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
						if (btt >= stope) {
							printf("\n  Search is Finish! Found: %d \n\n", nbFoundKey);
							exit(1);
						}
					}
				}
			}
		}
		//ph->isRunning = false;

	}
	if (rekey == 2) {
		int err = 0;
		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		ph->hasStarted = true;
		ph->rKeyRequest = false;

		while (2 > 1) {

			int N = nbit;
			char str[]{ "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" };
			int strN = 58;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << seed.c_str() << pass;
			std::string priv = ss.str();

			delete[] pass;

			bool isComp;
			key22 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

			std::stringstream ss1;
			ss1 << key22.GetBase16().c_str();
			std::string sv1 = ss1.str();

			std::stringstream ss2;
			ss2 << kisa.GetBase16().c_str();
			std::string sv2 = ss2.str();

			if (sv1 == sv2) {

				counters2 += 1;
			}
			else {
				int mnogo = key22.GetBitLength();

				if (mnogo == display) {

					kisa.Set(&key22);
					key.Set(&key22);
					input1 = priv.c_str();
					input2 = key;

					startP = secp->ComputePublicKey(&key);
					int i = 0;
					if (coinType == COIN_BTC) {
						switch (compMode) {
						case SEARCH_COMPRESSED:
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddresses(true, key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddress(true, key, i, startP);
								break;
							case (int)SEARCH_MODE_MX:
								checkMultiXPoints(true, key, i, startP);
								break;
							case (int)SEARCH_MODE_SX:
								checkSingleXPoint(true, key, i, startP);
								break;
							default:
								break;
							}
							break;
						case SEARCH_UNCOMPRESSED:
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddresses(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddress(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_MX:
								checkMultiXPoints(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_SX:
								checkSingleXPoint(false, key, i, startP);
								break;
							default:
								break;
							}
							break;
						case SEARCH_BOTH:
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddresses(true, key, i, startP);
								checkMultiAddresses(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddress(true, key, i, startP);
								checkSingleAddress(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_MX:
								checkMultiXPoints(true, key, i, startP);
								checkMultiXPoints(false, key, i, startP);
								break;
							case (int)SEARCH_MODE_SX:
								checkSingleXPoint(true, key, i, startP);
								checkSingleXPoint(false, key, i, startP);
								break;
							default:
								break;
							}
							break;
						}
					}
					else {
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddressesETH(key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddressETH(key, i, startP);
							break;
						default:
							break;
						}
					}
					counters[thId] += 1;
				}
				else {

					counters2 += 1;
				}
			}
		}
	}

	if (rekey == 3) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;
		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment(last);
			string input = str;

			if (thId == 0) {

				str0 = str;
				std::stringstream ss;
				ss << str << kstr0;
				std::string priv = ss.str();

				bool isComp;
				key0 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key0.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa0.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key0.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key0);
						kisa0.Set(&key0);
						input1 = priv;
						input2 = key;

						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 1) {
				str1 = str;
				std::stringstream ss;
				ss << str << kstr1;
				std::string priv = ss.str();

				bool isComp;
				key1 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key1.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa1.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key1.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key1);
						kisa1.Set(&key1);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 2) {

				str2 = str;
				std::stringstream ss;
				ss << str << kstr2;
				std::string priv = ss.str();

				bool isComp;
				key2 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key2.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa2.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key2.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key2);
						kisa2.Set(&key2);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 3) {

				str3 = str;
				std::stringstream ss;
				ss << str << kstr3;
				std::string priv = ss.str();

				bool isComp;
				key3 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key3.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa3.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key3.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key3);
						kisa3.Set(&key3);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 4) {

				str4 = str;
				std::stringstream ss;
				ss << str << kstr4;
				std::string priv = ss.str();

				bool isComp;
				key4 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key4.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa4.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key4.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key4);
						kisa4.Set(&key4);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 5) {

				str5 = str;
				std::stringstream ss;
				ss << str << kstr5;
				std::string priv = ss.str();

				bool isComp;
				key5 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key5.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa5.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key5.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key5);
						kisa5.Set(&key5);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 6) {

				str6 = str;
				std::stringstream ss;
				ss << str << kstr6;
				std::string priv = ss.str();

				bool isComp;
				key6 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key6.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa6.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key6.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key6);
						kisa6.Set(&key6);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 7) {

				str7 = str;
				std::stringstream ss;
				ss << str << kstr7;
				std::string priv = ss.str();

				bool isComp;
				key7 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key7.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa7.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key7.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key7);
						kisa7.Set(&key7);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 8) {

				str8 = str;
				std::stringstream ss;
				ss << str << kstr8;
				std::string priv = ss.str();

				bool isComp;
				key8 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key8.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa8.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key8.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key8);
						kisa8.Set(&key8);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 9) {

				str9 = str;
				std::stringstream ss;
				ss << str << kstr9;
				std::string priv = ss.str();

				bool isComp;
				key9 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key9.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa9.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key9.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key9);
						kisa9.Set(&key9);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 10) {

				str10 = str;
				std::stringstream ss;
				ss << str << kstr10;
				std::string priv = ss.str();

				bool isComp;
				key10 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key10.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa10.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key10.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key10);
						kisa10.Set(&key10);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 11) {

				str11 = str;
				std::stringstream ss;
				ss << str << kstr11;
				std::string priv = ss.str();

				bool isComp;
				key11 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key11.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa11.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key11.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key11);
						kisa11.Set(&key11);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 12) {

				str12 = str;
				std::stringstream ss;
				ss << str << kstr12;
				std::string priv = ss.str();

				bool isComp;
				key12 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				std::stringstream ss1;
				ss1 << key12.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa12.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key12.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key12);
						kisa12.Set(&key12);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 13) {

				str13 = str;
				std::stringstream ss;
				ss << str << kstr13;
				std::string priv = ss.str();

				bool isComp;
				key13 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key13.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa13.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key13.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key13);
						kisa13.Set(&key13);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 14) {

				str14 = str;
				std::stringstream ss;
				ss << str << kstr14;
				std::string priv = ss.str();

				bool isComp;
				key14 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key14.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa14.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key14.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key14);
						kisa14.Set(&key14);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 15) {

				str15 = str;
				std::stringstream ss;
				ss << str << kstr15;
				std::string priv = ss.str();

				bool isComp;
				key15 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key15.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa15.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key15.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key15);
						kisa15.Set(&key15);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 16) {

				str16 = str;
				std::stringstream ss;
				ss << str << kstr16;
				std::string priv = ss.str();

				bool isComp;
				key16 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key16.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa16.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key16.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key16);
						kisa16.Set(&key16);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 17) {

				str17 = str;
				std::stringstream ss;
				ss << str << kstr17;
				std::string priv = ss.str();

				bool isComp;
				key17 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key17.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa17.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key17.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key17);
						kisa17.Set(&key17);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 18) {

				str18 = str;
				std::stringstream ss;
				ss << str << kstr18;
				std::string priv = ss.str();

				bool isComp;
				key18 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key18.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa18.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key18.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key18);
						kisa18.Set(&key18);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 19) {

				str19 = str;
				std::stringstream ss;
				ss << str << kstr19;
				std::string priv = ss.str();

				bool isComp;
				key19 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key19.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa19.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key19.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key19);
						kisa19.Set(&key19);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 20) {

				str20 = str;
				std::stringstream ss;
				ss << str << kstr20;
				std::string priv = ss.str();

				bool isComp;
				key20 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key20.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa20.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key20.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key20);
						kisa20.Set(&key20);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 21) {

				str21 = str;
				std::stringstream ss;
				ss << str << kstr21;
				std::string priv = ss.str();

				bool isComp;
				key21 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key21.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa21.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key21.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key21);
						kisa21.Set(&key21);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 22) {

				str22 = str;
				std::stringstream ss;
				ss << str << kstr22;
				std::string priv = ss.str();

				bool isComp;
				key22 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key22.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa22.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key22.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key22);
						kisa22.Set(&key22);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 23) {

				str23 = str;
				std::stringstream ss;
				ss << str << kstr23;
				std::string priv = ss.str();

				bool isComp;
				key23 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key23.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa23.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key23.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key23);
						kisa23.Set(&key23);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 24) {

				str24 = str;
				std::stringstream ss;
				ss << str << kstr24;
				std::string priv = ss.str();

				bool isComp;
				key24 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key24.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa24.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key24.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key24);
						kisa24.Set(&key24);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 25) {

				str25 = str;
				std::stringstream ss;
				ss << str << kstr25;
				std::string priv = ss.str();

				bool isComp;
				key25 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key25.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa25.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key25.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key25);
						kisa25.Set(&key25);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 26) {

				str26 = str;
				std::stringstream ss;
				ss << str << kstr26;
				std::string priv = ss.str();

				bool isComp;
				key26 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key26.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa26.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key26.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key26);
						kisa26.Set(&key26);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 27) {

				str27 = str;
				std::stringstream ss;
				ss << str << kstr27;
				std::string priv = ss.str();

				bool isComp;
				key27 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key27.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa27.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key27.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key27);
						kisa27.Set(&key27);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 28) {

				str28 = str;
				std::stringstream ss;
				ss << str << kstr28;
				std::string priv = ss.str();

				bool isComp;
				key28 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key28.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa28.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key28.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key28);
						kisa28.Set(&key28);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 29) {

				str29 = str;
				std::stringstream ss;
				ss << str << kstr29;
				std::string priv = ss.str();

				bool isComp;
				key29 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key29.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa29.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key29.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key29);
						kisa29.Set(&key29);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 30) {

				str30 = str;
				std::stringstream ss;
				ss << str << kstr30;
				std::string priv = ss.str();

				bool isComp;
				key30 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key30.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa30.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key30.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key30);
						kisa30.Set(&key30);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 31) {
				str31 = str;
				std::stringstream ss;
				ss << str << kstr31;
				std::string priv = ss.str();

				bool isComp;
				key31 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key31.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa31.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key31.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key31);
						kisa31.Set(&key31);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 32) {

				str32 = str;
				std::stringstream ss;
				ss << str << kstr32;
				std::string priv = ss.str();

				bool isComp;
				key32 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key32.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa32.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key32.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key32);
						kisa32.Set(&key32);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 33) {

				str33 = str;
				std::stringstream ss;
				ss << str << kstr33;
				std::string priv = ss.str();

				bool isComp;
				key33 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key33.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa33.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key33.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key33);
						kisa33.Set(&key33);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 34) {

				str34 = str;
				std::stringstream ss;
				ss << str << kstr34;
				std::string priv = ss.str();

				bool isComp;
				key34 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key34.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa34.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key34.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key34);
						kisa34.Set(&key34);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 35) {

				str35 = str;
				std::stringstream ss;
				ss << str << kstr35;
				std::string priv = ss.str();

				bool isComp;
				key35 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key35.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa35.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key35.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key35);
						kisa35.Set(&key35);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 36) {
				str36 = str;
				std::stringstream ss;
				ss << str << kstr36;
				std::string priv = ss.str();

				bool isComp;
				key36 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key36.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa36.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key36.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key36);
						kisa36.Set(&key36);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 37) {

				str37 = str;
				std::stringstream ss;
				ss << str << kstr37;
				std::string priv = ss.str();

				bool isComp;
				key37 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key37.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa37.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key37.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key37);
						kisa37.Set(&key37);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 38) {

				str38 = str;
				std::stringstream ss;
				ss << str << kstr38;
				std::string priv = ss.str();

				bool isComp;
				key38 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key38.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa38.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key38.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key38);
						kisa38.Set(&key38);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 39) {

				str39 = str;
				std::stringstream ss;
				ss << str << kstr39;
				std::string priv = ss.str();

				bool isComp;
				key39 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key39.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa39.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key39.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key39);
						kisa39.Set(&key39);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 40) {

				str40 = str;
				std::stringstream ss;
				ss << str << kstr40;
				std::string priv = ss.str();

				bool isComp;
				key40 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key40.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa40.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key40.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key40);
						kisa40.Set(&key40);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 41) {

				str41 = str;
				std::stringstream ss;
				ss << str << kstr41;
				std::string priv = ss.str();

				bool isComp;
				key41 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key41.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa41.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key41.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key41);
						kisa41.Set(&key41);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 42) {
				str42 = str;
				std::stringstream ss;
				ss << str << kstr42;
				std::string priv = ss.str();

				bool isComp;
				key42 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key42.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa42.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key42.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key42);
						kisa42.Set(&key42);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 43) {
				str43 = str;
				std::stringstream ss;
				ss << str << kstr43;
				std::string priv = ss.str();

				bool isComp;
				key43 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key43.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa43.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key43.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key43);
						kisa43.Set(&key43);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 44) {

				str44 = str;
				std::stringstream ss;
				ss << str << kstr44;
				std::string priv = ss.str();

				bool isComp;
				key44 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key44.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa44.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key44.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key44);
						kisa44.Set(&key44);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 45) {

				str45 = str;
				std::stringstream ss;
				ss << str << kstr45;
				std::string priv = ss.str();

				bool isComp;
				key45 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key45.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa45.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key45.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key45);
						kisa45.Set(&key45);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 46) {

				str46 = str;
				std::stringstream ss;
				ss << str << kstr46;
				std::string priv = ss.str();

				bool isComp;
				key46 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key46.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa46.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key46.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key46);
						kisa46.Set(&key46);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 47) {

				str47 = str;
				std::stringstream ss;
				ss << str << kstr47;
				std::string priv = ss.str();

				bool isComp;
				key47 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key47.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa47.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key47.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key47);
						kisa47.Set(&key47);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 48) {

				str48 = str;
				std::stringstream ss;
				ss << str << kstr48;
				std::string priv = ss.str();

				bool isComp;
				key48 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key48.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa48.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key48.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key48);
						kisa48.Set(&key48);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 49) {

				str49 = str;
				std::stringstream ss;
				ss << str << kstr49;
				std::string priv = ss.str();

				bool isComp;
				key49 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key49.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa49.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key49.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key49);
						kisa49.Set(&key49);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 50) {

				str50 = str;
				std::stringstream ss;
				ss << str << kstr50;
				std::string priv = ss.str();

				bool isComp;
				key50 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key50.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa50.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key50.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key50);
						kisa50.Set(&key50);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 51) {

				str51 = str;
				std::stringstream ss;
				ss << str << kstr51;
				std::string priv = ss.str();

				bool isComp;
				key51 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key51.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa51.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key51.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key51);
						kisa51.Set(&key51);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 52) {
				str52 = str;
				std::stringstream ss;
				ss << str << kstr52;
				std::string priv = ss.str();

				bool isComp;
				key52 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key52.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa52.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key52.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key52);
						kisa52.Set(&key52);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 53) {

				str53 = str;
				std::stringstream ss;
				ss << str << kstr53;
				std::string priv = ss.str();

				bool isComp;
				key53 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key53.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa53.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key53.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key53);
						kisa53.Set(&key53);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 54) {

				str54 = str;
				std::stringstream ss;
				ss << str << kstr54;
				std::string priv = ss.str();

				bool isComp;
				key54 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key54.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa54.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key54.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key54);
						kisa54.Set(&key54);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 55) {

				str55 = str;
				std::stringstream ss;
				ss << str << kstr55;
				std::string priv = ss.str();

				bool isComp;
				key55 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key55.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa55.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key55.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key55);
						kisa55.Set(&key55);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 56) {

				str56 = str;
				std::stringstream ss;
				ss << str << kstr56;
				std::string priv = ss.str();

				bool isComp;
				key56 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key56.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa56.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key56.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key56);
						kisa56.Set(&key56);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 57) {

				str57 = str;
				std::stringstream ss;
				ss << str << kstr57;
				std::string priv = ss.str();

				bool isComp;
				key57 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key57.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa57.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key57.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key57);
						kisa57.Set(&key57);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 58) {

				str58 = str;
				std::stringstream ss;
				ss << str << kstr58;
				std::string priv = ss.str();

				bool isComp;
				key58 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key58.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa58.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key58.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key58);
						kisa58.Set(&key58);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 59) {

				str59 = str;
				std::stringstream ss;
				ss << str << kstr59;
				std::string priv = ss.str();

				bool isComp;
				key59 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key59.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa59.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key59.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key59);
						kisa59.Set(&key59);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 60) {

				str60 = str;
				std::stringstream ss;
				ss << str << kstr60;
				std::string priv = ss.str();

				bool isComp;
				key60 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key60.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa60.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key60.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key60);
						kisa60.Set(&key60);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 61) {

				str61 = str;
				std::stringstream ss;
				ss << str << kstr61;
				std::string priv = ss.str();

				bool isComp;
				key61 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key61.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa61.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key61.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key61);
						kisa61.Set(&key61);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 62) {

				str62 = str;
				std::stringstream ss;
				ss << str << kstr62;
				std::string priv = ss.str();

				bool isComp;
				key62 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key62.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa62.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key62.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key62);
						kisa62.Set(&key62);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 63) {

				str63 = str;
				std::stringstream ss;
				ss << str << kstr63;
				std::string priv = ss.str();

				bool isComp;
				key63 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key63.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa63.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key63.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key63);
						kisa63.Set(&key63);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}
			if (thId == 64) {

				str64 = str;
				std::stringstream ss;
				ss << str << kstr64;
				std::string priv = ss.str();

				bool isComp;
				key64 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				std::stringstream ss1;
				ss1 << key64.GetBase16().c_str();
				std::string sv1 = ss1.str();

				std::stringstream ss2;
				ss2 << kisa64.GetBase16().c_str();
				std::string sv2 = ss2.str();
				int mnogo = key64.GetBitLength();

				if (sv1 == sv2) {
					counters2 += 1;
				}
				else {

					if (mnogo == display) {

						key.Set(&key64);
						kisa64.Set(&key64);
						startP = secp->ComputePublicKey(&key);
						int i = 0;
						if (coinType == COIN_BTC) {
							switch (compMode) {
							case SEARCH_COMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_UNCOMPRESSED:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							case SEARCH_BOTH:
								switch (searchMode) {
								case (int)SEARCH_MODE_MA:
									checkMultiAddresses(true, key, i, startP);
									checkMultiAddresses(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SA:
									checkSingleAddress(true, key, i, startP);
									checkSingleAddress(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_MX:
									checkMultiXPoints(true, key, i, startP);
									checkMultiXPoints(false, key, i, startP);
									break;
								case (int)SEARCH_MODE_SX:
									checkSingleXPoint(true, key, i, startP);
									checkSingleXPoint(false, key, i, startP);
									break;
								default:
									break;
								}
								break;
							}
						}
						else {
							switch (searchMode) {
							case (int)SEARCH_MODE_MA:
								checkMultiAddressesETH(key, i, startP);
								break;
							case (int)SEARCH_MODE_SA:
								checkSingleAddressETH(key, i, startP);
								break;
							default:
								break;
							}
						}
						counters[thId] += 1;
					}
					else {
						counters2 += 1;
					}
				}
			}

		} while (compare(last, str));
	}

	if (rekey == 4) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;

		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment2(last);

			if (nbit > 4) {

				if (vremyax == nbit) {

					int asciiArray[256];
					char ch;
					int charconv;
					for (int i = 0; i < 256; i++)
						asciiArray[i] = 0;
					for (unsigned int i = 0; i < str.length(); i++)
					{
						ch = str[i];
						charconv = static_cast<int>(ch);
						asciiArray[charconv]++;
					}

					for (unsigned int i = 0; i < str.length(); i++)
					{
						char static alreadyprinted;
						char ch = str[i];

						if ((asciiArray[ch] > 2) && (ch != alreadyprinted) && (find(alreadyprintedcharacters.begin(), alreadyprintedcharacters.end(), ch) == alreadyprintedcharacters.end()))
						{
							string proverka = str;
							string proverka1 = regex_replace(proverka, regex("AAA"), "AAB");
							string proverka2 = regex_replace(proverka1, regex("AAa"), "AAb");
							string proverka3 = regex_replace(proverka2, regex("Aaa"), "Aab");
							string proverka4 = regex_replace(proverka3, regex("aaa"), "aab");
							string proverka5 = regex_replace(proverka4, regex("aaA"), "aaB");
							string proverka6 = regex_replace(proverka5, regex("aAA"), "aAB");
							string proverka7 = regex_replace(proverka6, regex("aAa"), "aAb");
							string proverka8 = regex_replace(proverka7, regex("AaA"), "AaB");
							string proverka9 = regex_replace(proverka8, regex("BBB"), "BBC");
							string proverka10 = regex_replace(proverka9, regex("BBb"), "BBc");
							string proverka11 = regex_replace(proverka10, regex("Bbb"), "Bbc");
							string proverka12 = regex_replace(proverka11, regex("bbb"), "bbc");
							string proverka13 = regex_replace(proverka12, regex("bbB"), "bbC");
							string proverka14 = regex_replace(proverka13, regex("bBB"), "bBC");
							string proverka15 = regex_replace(proverka14, regex("bBb"), "bBc");
							string proverka16 = regex_replace(proverka15, regex("BbB"), "BbC");
							string proverka17 = regex_replace(proverka16, regex("CCC"), "CCD");
							string proverka18 = regex_replace(proverka17, regex("CCc"), "CCd");
							string proverka19 = regex_replace(proverka18, regex("Ccc"), "Ccd");
							string proverka20 = regex_replace(proverka19, regex("ccc"), "ccd");
							string proverka21 = regex_replace(proverka20, regex("ccC"), "ccD");
							string proverka22 = regex_replace(proverka21, regex("cCC"), "cCD");
							string proverka23 = regex_replace(proverka22, regex("cCc"), "cCd");
							string proverka24 = regex_replace(proverka23, regex("CcC"), "CcD");
							string proverka25 = regex_replace(proverka24, regex("DDD"), "DDE");
							string proverka26 = regex_replace(proverka25, regex("DDd"), "DDe");
							string proverka27 = regex_replace(proverka26, regex("Ddd"), "Dde");
							string proverka28 = regex_replace(proverka27, regex("ddd"), "dde");
							string proverka29 = regex_replace(proverka28, regex("ddD"), "ddE");
							string proverka30 = regex_replace(proverka29, regex("dDD"), "dDE");
							string proverka31 = regex_replace(proverka30, regex("dDd"), "dDe");
							string proverka32 = regex_replace(proverka31, regex("DdD"), "DdE");
							string proverka33 = regex_replace(proverka32, regex("EEE"), "EEF");
							string proverka34 = regex_replace(proverka33, regex("EEe"), "EEf");
							string proverka35 = regex_replace(proverka34, regex("Eee"), "Eef");
							string proverka36 = regex_replace(proverka35, regex("eee"), "eef");
							string proverka37 = regex_replace(proverka36, regex("eeE"), "eeF");
							string proverka38 = regex_replace(proverka37, regex("eEE"), "eEF");
							string proverka39 = regex_replace(proverka38, regex("eEe"), "eEf");
							string proverka40 = regex_replace(proverka39, regex("EeE"), "EeF");
							string proverka41 = regex_replace(proverka40, regex("FFF"), "FFG");
							string proverka42 = regex_replace(proverka41, regex("FFf"), "FFg");
							string proverka43 = regex_replace(proverka42, regex("Fff"), "Ffg");
							string proverka44 = regex_replace(proverka43, regex("fff"), "ffg");
							string proverka45 = regex_replace(proverka44, regex("ffF"), "ffG");
							string proverka46 = regex_replace(proverka45, regex("fFF"), "fFG");
							string proverka47 = regex_replace(proverka46, regex("fFf"), "fFg");
							string proverka48 = regex_replace(proverka47, regex("FfF"), "FfG");
							string proverka49 = regex_replace(proverka48, regex("GGG"), "GGH");
							string proverka50 = regex_replace(proverka49, regex("GGg"), "GGh");
							string proverka51 = regex_replace(proverka50, regex("Ggg"), "Ggh");
							string proverka52 = regex_replace(proverka51, regex("ggg"), "ggh");
							string proverka53 = regex_replace(proverka52, regex("ggG"), "ggH");
							string proverka54 = regex_replace(proverka53, regex("gGG"), "gGH");
							string proverka55 = regex_replace(proverka54, regex("gGg"), "gGh");
							string proverka56 = regex_replace(proverka55, regex("GgG"), "GgH");
							string proverka57 = regex_replace(proverka56, regex("HHH"), "HHI");
							string proverka58 = regex_replace(proverka57, regex("HHh"), "HHi");
							string proverka59 = regex_replace(proverka58, regex("Hhh"), "Hhi");
							string proverka60 = regex_replace(proverka59, regex("hhh"), "hhi");
							string proverka61 = regex_replace(proverka60, regex("hhH"), "hhI");
							string proverka62 = regex_replace(proverka61, regex("hHH"), "hHI");
							string proverka63 = regex_replace(proverka62, regex("hHh"), "hHi");
							string proverka64 = regex_replace(proverka63, regex("HhH"), "HhI");
							string proverka65 = regex_replace(proverka64, regex("III"), "IIJ");
							string proverka66 = regex_replace(proverka65, regex("IIi"), "IIj");
							string proverka67 = regex_replace(proverka66, regex("Iii"), "Iij");
							string proverka68 = regex_replace(proverka67, regex("iii"), "iij");
							string proverka69 = regex_replace(proverka68, regex("iiI"), "iiJ");
							string proverka70 = regex_replace(proverka69, regex("iII"), "iIJ");
							string proverka71 = regex_replace(proverka70, regex("iIi"), "iIj");
							string proverka72 = regex_replace(proverka71, regex("IiI"), "IiJ");
							string proverka73 = regex_replace(proverka72, regex("JJJ"), "JJK");
							string proverka74 = regex_replace(proverka73, regex("JJj"), "JJk");
							string proverka75 = regex_replace(proverka74, regex("Jjj"), "Jjk");
							string proverka76 = regex_replace(proverka75, regex("jjj"), "jjk");
							string proverka77 = regex_replace(proverka76, regex("jjJ"), "jjK");
							string proverka78 = regex_replace(proverka77, regex("jJJ"), "jJK");
							string proverka79 = regex_replace(proverka78, regex("jJj"), "jJk");
							string proverka80 = regex_replace(proverka79, regex("JjJ"), "JjK");
							string proverka81 = regex_replace(proverka80, regex("KKK"), "KKL");
							string proverka82 = regex_replace(proverka81, regex("KKk"), "KKl");
							string proverka83 = regex_replace(proverka82, regex("Kkk"), "Kkl");
							string proverka84 = regex_replace(proverka83, regex("kkk"), "kkl");
							string proverka85 = regex_replace(proverka84, regex("kkK"), "kkL");
							string proverka86 = regex_replace(proverka85, regex("kKK"), "kKL");
							string proverka87 = regex_replace(proverka86, regex("kKk"), "kKl");
							string proverka88 = regex_replace(proverka87, regex("KkK"), "KkL");
							string proverka89 = regex_replace(proverka88, regex("LLL"), "LLM");
							string proverka90 = regex_replace(proverka89, regex("LLl"), "LLm");
							string proverka91 = regex_replace(proverka90, regex("Lll"), "Llm");
							string proverka92 = regex_replace(proverka91, regex("lll"), "llm");
							string proverka93 = regex_replace(proverka92, regex("llL"), "llM");
							string proverka94 = regex_replace(proverka93, regex("lLL"), "lLM");
							string proverka95 = regex_replace(proverka94, regex("lLl"), "lLm");
							string proverka96 = regex_replace(proverka95, regex("LlL"), "LlM");
							string proverka97 = regex_replace(proverka96, regex("MMM"), "MMN");
							string proverka98 = regex_replace(proverka97, regex("MMm"), "MMn");
							string proverka99 = regex_replace(proverka98, regex("Mmm"), "Mmn");
							string proverka100 = regex_replace(proverka99, regex("mmm"), "mmn");
							string proverka101 = regex_replace(proverka100, regex("mmM"), "mmN");
							string proverka102 = regex_replace(proverka101, regex("mMM"), "mMN");
							string proverka103 = regex_replace(proverka102, regex("mMm"), "mMn");
							string proverka104 = regex_replace(proverka103, regex("MmM"), "MmN");
							string proverka105 = regex_replace(proverka104, regex("NNN"), "NNO");
							string proverka106 = regex_replace(proverka105, regex("NNn"), "NNo");
							string proverka107 = regex_replace(proverka106, regex("Nnn"), "Nno");
							string proverka108 = regex_replace(proverka107, regex("nnn"), "nno");
							string proverka109 = regex_replace(proverka108, regex("nnN"), "nnO");
							string proverka110 = regex_replace(proverka109, regex("nNN"), "nNO");
							string proverka111 = regex_replace(proverka110, regex("nNn"), "nNo");
							string proverka112 = regex_replace(proverka111, regex("NnN"), "NnO");
							string proverka113 = regex_replace(proverka112, regex("OOO"), "OOP");
							string proverka114 = regex_replace(proverka113, regex("OOo"), "OOp");
							string proverka115 = regex_replace(proverka114, regex("Ooo"), "Oop");
							string proverka116 = regex_replace(proverka115, regex("ooo"), "oop");
							string proverka117 = regex_replace(proverka116, regex("ooO"), "ooP");
							string proverka118 = regex_replace(proverka117, regex("oOO"), "oOP");
							string proverka119 = regex_replace(proverka118, regex("oOo"), "oOp");
							string proverka120 = regex_replace(proverka119, regex("OoO"), "OoP");
							string proverka121 = regex_replace(proverka120, regex("PPP"), "PPQ");
							string proverka122 = regex_replace(proverka121, regex("PPp"), "PPq");
							string proverka123 = regex_replace(proverka122, regex("Ppp"), "Ppq");
							string proverka124 = regex_replace(proverka123, regex("ppp"), "ppq");
							string proverka125 = regex_replace(proverka124, regex("ppP"), "ppQ");
							string proverka126 = regex_replace(proverka125, regex("pPP"), "pPQ");
							string proverka127 = regex_replace(proverka126, regex("pPp"), "pPq");
							string proverka128 = regex_replace(proverka127, regex("PpP"), "PpQ");
							string proverka129 = regex_replace(proverka128, regex("QQQ"), "QQR");
							string proverka130 = regex_replace(proverka129, regex("QQq"), "QQr");
							string proverka131 = regex_replace(proverka130, regex("Qqq"), "Qqr");
							string proverka132 = regex_replace(proverka131, regex("qqq"), "qqr");
							string proverka133 = regex_replace(proverka132, regex("qqQ"), "qqR");
							string proverka134 = regex_replace(proverka133, regex("qQQ"), "qQR");
							string proverka135 = regex_replace(proverka134, regex("qQq"), "qQr");
							string proverka136 = regex_replace(proverka135, regex("QqQ"), "QqR");
							string proverka137 = regex_replace(proverka136, regex("RRR"), "RRS");
							string proverka138 = regex_replace(proverka137, regex("RRr"), "RRs");
							string proverka139 = regex_replace(proverka138, regex("Rrr"), "Rrs");
							string proverka140 = regex_replace(proverka139, regex("rrr"), "rrs");
							string proverka141 = regex_replace(proverka140, regex("rrR"), "rrS");
							string proverka142 = regex_replace(proverka141, regex("rRR"), "rRS");
							string proverka143 = regex_replace(proverka142, regex("rRr"), "rRs");
							string proverka144 = regex_replace(proverka143, regex("RrR"), "RrS");
							string proverka145 = regex_replace(proverka144, regex("SSS"), "SST");
							string proverka146 = regex_replace(proverka145, regex("SSs"), "SSt");
							string proverka147 = regex_replace(proverka146, regex("Sss"), "Sst");
							string proverka148 = regex_replace(proverka147, regex("sss"), "sst");
							string proverka149 = regex_replace(proverka148, regex("ssS"), "ssT");
							string proverka150 = regex_replace(proverka149, regex("sSS"), "sST");
							string proverka151 = regex_replace(proverka150, regex("sSs"), "sSt");
							string proverka152 = regex_replace(proverka151, regex("SsS"), "SsT");
							string proverka153 = regex_replace(proverka152, regex("TTT"), "TTU");
							string proverka154 = regex_replace(proverka153, regex("TTt"), "TTu");
							string proverka155 = regex_replace(proverka154, regex("Ttt"), "Ttu");
							string proverka156 = regex_replace(proverka155, regex("ttt"), "ttu");
							string proverka157 = regex_replace(proverka156, regex("ttT"), "ttU");
							string proverka158 = regex_replace(proverka157, regex("tTT"), "tTU");
							string proverka159 = regex_replace(proverka158, regex("tTt"), "tTu");
							string proverka160 = regex_replace(proverka159, regex("TtT"), "TtU");
							string proverka161 = regex_replace(proverka160, regex("UUU"), "UUV");
							string proverka162 = regex_replace(proverka161, regex("UUu"), "UUv");
							string proverka163 = regex_replace(proverka162, regex("Uuu"), "Uvv");
							string proverka164 = regex_replace(proverka163, regex("uuu"), "uuv");
							string proverka165 = regex_replace(proverka164, regex("uuU"), "uuV");
							string proverka166 = regex_replace(proverka165, regex("uUU"), "uUV");
							string proverka167 = regex_replace(proverka166, regex("uUu"), "uUv");
							string proverka168 = regex_replace(proverka167, regex("UuU"), "UuV");
							string proverka169 = regex_replace(proverka168, regex("VVV"), "VVW");
							string proverka170 = regex_replace(proverka169, regex("VVv"), "VVw");
							string proverka171 = regex_replace(proverka170, regex("Vvv"), "Vvw");
							string proverka172 = regex_replace(proverka171, regex("vvv"), "vvw");
							string proverka173 = regex_replace(proverka172, regex("vvV"), "vvW");
							string proverka174 = regex_replace(proverka173, regex("vVV"), "vVW");
							string proverka175 = regex_replace(proverka174, regex("vVv"), "vVw");
							string proverka176 = regex_replace(proverka175, regex("VvV"), "VvW");
							string proverka177 = regex_replace(proverka176, regex("WWW"), "WWX");
							string proverka178 = regex_replace(proverka177, regex("WWw"), "WWx");
							string proverka179 = regex_replace(proverka178, regex("Www"), "Wwx");
							string proverka180 = regex_replace(proverka179, regex("www"), "wwx");
							string proverka181 = regex_replace(proverka180, regex("wwW"), "wwX");
							string proverka182 = regex_replace(proverka181, regex("wWW"), "wWX");
							string proverka183 = regex_replace(proverka182, regex("wWw"), "wWx");
							string proverka184 = regex_replace(proverka183, regex("WwW"), "WwX");
							string proverka185 = regex_replace(proverka184, regex("XXX"), "XXY");
							string proverka186 = regex_replace(proverka185, regex("XXx"), "XXy");
							string proverka187 = regex_replace(proverka186, regex("Xxx"), "Xxy");
							string proverka188 = regex_replace(proverka187, regex("xxx"), "xxy");
							string proverka189 = regex_replace(proverka188, regex("xxX"), "xxY");
							string proverka190 = regex_replace(proverka189, regex("xXX"), "xXY");
							string proverka191 = regex_replace(proverka190, regex("xXx"), "xXy");
							string proverka192 = regex_replace(proverka191, regex("XxX"), "XxY");
							string proverka193 = regex_replace(proverka192, regex("YYY"), "YYZ");
							string proverka194 = regex_replace(proverka193, regex("YYy"), "YYz");
							string proverka195 = regex_replace(proverka194, regex("Yyy"), "Yyz");
							string proverka196 = regex_replace(proverka195, regex("yyy"), "yyz");
							string proverka197 = regex_replace(proverka196, regex("yyY"), "yyZ");
							string proverka198 = regex_replace(proverka197, regex("yYY"), "yYZ");
							string proverka199 = regex_replace(proverka198, regex("yYy"), "yYz");
							string proverka200 = regex_replace(proverka199, regex("YyY"), "YyZ");

							if (proverka200 != str) {
								zamena = "Filter 3 litters + Replace: " + str + " -> " + proverka200;
								//SetConsoleTitle(zamena.c_str());
								str = proverka200;
								counters2 += 1;
							}
						}
					}
				}
			}

			if (thId == 0) {
				str0 = str;
			}
			if (thId == 1) {
				str1 = str;
			}
			if (thId == 2) {
				str2 = str;
			}
			if (thId == 3) {
				str3 = str;
			}
			if (thId == 4) {
				str4 = str;
			}
			if (thId == 5) {
				str5 = str;
			}
			if (thId == 6) {
				str6 = str;
			}
			if (thId == 7) {
				str7 = str;
			}
			if (thId == 8) {
				str8 = str;
			}
			if (thId == 9) {
				str9 = str;
			}
			if (thId == 10) {
				str10 = str;
			}
			if (thId == 11) {
				str11 = str;
			}
			if (thId == 12) {
				str12 = str;
			}
			if (thId == 13) {
				str13 = str;
			}
			if (thId == 14) {
				str14 = str;
			}
			if (thId == 15) {
				str15 = str;
			}
			if (thId == 16) {
				str16 = str;
			}
			if (thId == 17) {
				str17 = str;
			}
			if (thId == 18) {
				str18 = str;
			}
			if (thId == 19) {
				str19 = str;
			}
			if (thId == 20) {
				str20 = str;
			}
			if (thId == 21) {
				str21 = str;
			}
			if (thId == 22) {
				str22 = str;
			}
			if (thId == 23) {
				str23 = str;
			}
			if (thId == 24) {
				str24 = str;
			}
			if (thId == 25) {
				str25 = str;
			}
			if (thId == 26) {
				str26 = str;
			}
			if (thId == 27) {
				str27 = str;
			}
			if (thId == 28) {
				str28 = str;
			}
			if (thId == 29) {
				str29 = str;
			}
			if (thId == 30) {
				str30 = str;
			}
			if (thId == 31) {
				str31 = str;
			}
			if (thId == 32) {
				str32 = str;
			}
			if (thId == 33) {
				str33 = str;
			}
			if (thId == 34) {
				str34 = str;
			}
			if (thId == 35) {
				str35 = str;
			}
			if (thId == 36) {
				str36 = str;
			}
			if (thId == 37) {
				str37 = str;
			}
			if (thId == 38) {
				str38 = str;
			}
			if (thId == 39) {
				str39 = str;
			}
			if (thId == 40) {
				str40 = str;
			}
			if (thId == 41) {
				str41 = str;
			}
			if (thId == 42) {
				str42 = str;
			}
			if (thId == 43) {
				str43 = str;
			}
			if (thId == 44) {
				str44 = str;
			}
			if (thId == 45) {
				str45 = str;
			}
			if (thId == 46) {
				str46 = str;
			}
			if (thId == 47) {
				str47 = str;
			}
			if (thId == 48) {
				str48 = str;
			}
			if (thId == 49) {
				str49 = str;
			}
			if (thId == 50) {
				str50 = str;
			}
			if (thId == 51) {
				str51 = str;
			}
			if (thId == 52) {
				str52 = str;
			}
			if (thId == 53) {
				str53 = str;
			}
			if (thId == 54) {
				str54 = str;
			}
			if (thId == 55) {
				str55 = str;
			}
			if (thId == 56) {
				str56 = str;
			}
			if (thId == 57) {
				str57 = str;
			}
			if (thId == 58) {
				str58 = str;
			}
			if (thId == 59) {
				str59 = str;
			}
			if (thId == 60) {
				str60 = str;
			}
			if (thId == 61) {
				str61 = str;
			}
			if (thId == 62) {
				str62 = str;
			}
			if (thId == 63) {
				str63 = str;
			}
			if (thId == 64) {
				str64 = str;
			}

			string input = str;
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);
			if (thId == 0) {
				input1 = str;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;

		} while (compare2(last, str));

	}
	if (rekey == 5) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;

		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment3(last);

			if (nbit > 4) {

				if (vremyax == nbit) {

					int asciiArray[256];
					char ch;
					int charconv;
					for (int i = 0; i < 256; i++)
						asciiArray[i] = 0;
					for (unsigned int i = 0; i < str.length(); i++)
					{
						ch = str[i];
						charconv = static_cast<int>(ch);
						asciiArray[charconv]++;
					}

					for (unsigned int i = 0; i < str.length(); i++)
					{
						char static alreadyprinted;
						char ch = str[i];

						if ((asciiArray[ch] > 2) && (ch != alreadyprinted) && (find(alreadyprintedcharacters.begin(), alreadyprintedcharacters.end(), ch) == alreadyprintedcharacters.end()))
						{
							string proverka = str;
							string proverka1 = regex_replace(proverka, regex("AAA"), "AAB");
							string proverka2 = regex_replace(proverka1, regex("AAa"), "AAb");
							string proverka3 = regex_replace(proverka2, regex("Aaa"), "Aab");
							string proverka4 = regex_replace(proverka3, regex("aaa"), "aab");
							string proverka5 = regex_replace(proverka4, regex("aaA"), "aaB");
							string proverka6 = regex_replace(proverka5, regex("aAA"), "aAB");
							string proverka7 = regex_replace(proverka6, regex("aAa"), "aAb");
							string proverka8 = regex_replace(proverka7, regex("AaA"), "AaB");
							string proverka9 = regex_replace(proverka8, regex("BBB"), "BBC");
							string proverka10 = regex_replace(proverka9, regex("BBb"), "BBc");
							string proverka11 = regex_replace(proverka10, regex("Bbb"), "Bbc");
							string proverka12 = regex_replace(proverka11, regex("bbb"), "bbc");
							string proverka13 = regex_replace(proverka12, regex("bbB"), "bbC");
							string proverka14 = regex_replace(proverka13, regex("bBB"), "bBC");
							string proverka15 = regex_replace(proverka14, regex("bBb"), "bBc");
							string proverka16 = regex_replace(proverka15, regex("BbB"), "BbC");
							string proverka17 = regex_replace(proverka16, regex("CCC"), "CCD");
							string proverka18 = regex_replace(proverka17, regex("CCc"), "CCd");
							string proverka19 = regex_replace(proverka18, regex("Ccc"), "Ccd");
							string proverka20 = regex_replace(proverka19, regex("ccc"), "ccd");
							string proverka21 = regex_replace(proverka20, regex("ccC"), "ccD");
							string proverka22 = regex_replace(proverka21, regex("cCC"), "cCD");
							string proverka23 = regex_replace(proverka22, regex("cCc"), "cCd");
							string proverka24 = regex_replace(proverka23, regex("CcC"), "CcD");
							string proverka25 = regex_replace(proverka24, regex("DDD"), "DDE");
							string proverka26 = regex_replace(proverka25, regex("DDd"), "DDe");
							string proverka27 = regex_replace(proverka26, regex("Ddd"), "Dde");
							string proverka28 = regex_replace(proverka27, regex("ddd"), "dde");
							string proverka29 = regex_replace(proverka28, regex("ddD"), "ddE");
							string proverka30 = regex_replace(proverka29, regex("dDD"), "dDE");
							string proverka31 = regex_replace(proverka30, regex("dDd"), "dDe");
							string proverka32 = regex_replace(proverka31, regex("DdD"), "DdE");
							string proverka33 = regex_replace(proverka32, regex("EEE"), "EEF");
							string proverka34 = regex_replace(proverka33, regex("EEe"), "EEf");
							string proverka35 = regex_replace(proverka34, regex("Eee"), "Eef");
							string proverka36 = regex_replace(proverka35, regex("eee"), "eef");
							string proverka37 = regex_replace(proverka36, regex("eeE"), "eeF");
							string proverka38 = regex_replace(proverka37, regex("eEE"), "eEF");
							string proverka39 = regex_replace(proverka38, regex("eEe"), "eEf");
							string proverka40 = regex_replace(proverka39, regex("EeE"), "EeF");
							string proverka41 = regex_replace(proverka40, regex("FFF"), "FFG");
							string proverka42 = regex_replace(proverka41, regex("FFf"), "FFg");
							string proverka43 = regex_replace(proverka42, regex("Fff"), "Ffg");
							string proverka44 = regex_replace(proverka43, regex("fff"), "ffg");
							string proverka45 = regex_replace(proverka44, regex("ffF"), "ffG");
							string proverka46 = regex_replace(proverka45, regex("fFF"), "fFG");
							string proverka47 = regex_replace(proverka46, regex("fFf"), "fFg");
							string proverka48 = regex_replace(proverka47, regex("FfF"), "FfG");
							string proverka49 = regex_replace(proverka48, regex("GGG"), "GGH");
							string proverka50 = regex_replace(proverka49, regex("GGg"), "GGh");
							string proverka51 = regex_replace(proverka50, regex("Ggg"), "Ggh");
							string proverka52 = regex_replace(proverka51, regex("ggg"), "ggh");
							string proverka53 = regex_replace(proverka52, regex("ggG"), "ggH");
							string proverka54 = regex_replace(proverka53, regex("gGG"), "gGH");
							string proverka55 = regex_replace(proverka54, regex("gGg"), "gGh");
							string proverka56 = regex_replace(proverka55, regex("GgG"), "GgH");
							string proverka57 = regex_replace(proverka56, regex("HHH"), "HHI");
							string proverka58 = regex_replace(proverka57, regex("HHh"), "HHi");
							string proverka59 = regex_replace(proverka58, regex("Hhh"), "Hhi");
							string proverka60 = regex_replace(proverka59, regex("hhh"), "hhi");
							string proverka61 = regex_replace(proverka60, regex("hhH"), "hhI");
							string proverka62 = regex_replace(proverka61, regex("hHH"), "hHI");
							string proverka63 = regex_replace(proverka62, regex("hHh"), "hHi");
							string proverka64 = regex_replace(proverka63, regex("HhH"), "HhI");
							string proverka65 = regex_replace(proverka64, regex("III"), "IIJ");
							string proverka66 = regex_replace(proverka65, regex("IIi"), "IIj");
							string proverka67 = regex_replace(proverka66, regex("Iii"), "Iij");
							string proverka68 = regex_replace(proverka67, regex("iii"), "iij");
							string proverka69 = regex_replace(proverka68, regex("iiI"), "iiJ");
							string proverka70 = regex_replace(proverka69, regex("iII"), "iIJ");
							string proverka71 = regex_replace(proverka70, regex("iIi"), "iIj");
							string proverka72 = regex_replace(proverka71, regex("IiI"), "IiJ");
							string proverka73 = regex_replace(proverka72, regex("JJJ"), "JJK");
							string proverka74 = regex_replace(proverka73, regex("JJj"), "JJk");
							string proverka75 = regex_replace(proverka74, regex("Jjj"), "Jjk");
							string proverka76 = regex_replace(proverka75, regex("jjj"), "jjk");
							string proverka77 = regex_replace(proverka76, regex("jjJ"), "jjK");
							string proverka78 = regex_replace(proverka77, regex("jJJ"), "jJK");
							string proverka79 = regex_replace(proverka78, regex("jJj"), "jJk");
							string proverka80 = regex_replace(proverka79, regex("JjJ"), "JjK");
							string proverka81 = regex_replace(proverka80, regex("KKK"), "KKL");
							string proverka82 = regex_replace(proverka81, regex("KKk"), "KKl");
							string proverka83 = regex_replace(proverka82, regex("Kkk"), "Kkl");
							string proverka84 = regex_replace(proverka83, regex("kkk"), "kkl");
							string proverka85 = regex_replace(proverka84, regex("kkK"), "kkL");
							string proverka86 = regex_replace(proverka85, regex("kKK"), "kKL");
							string proverka87 = regex_replace(proverka86, regex("kKk"), "kKl");
							string proverka88 = regex_replace(proverka87, regex("KkK"), "KkL");
							string proverka89 = regex_replace(proverka88, regex("LLL"), "LLM");
							string proverka90 = regex_replace(proverka89, regex("LLl"), "LLm");
							string proverka91 = regex_replace(proverka90, regex("Lll"), "Llm");
							string proverka92 = regex_replace(proverka91, regex("lll"), "llm");
							string proverka93 = regex_replace(proverka92, regex("llL"), "llM");
							string proverka94 = regex_replace(proverka93, regex("lLL"), "lLM");
							string proverka95 = regex_replace(proverka94, regex("lLl"), "lLm");
							string proverka96 = regex_replace(proverka95, regex("LlL"), "LlM");
							string proverka97 = regex_replace(proverka96, regex("MMM"), "MMN");
							string proverka98 = regex_replace(proverka97, regex("MMm"), "MMn");
							string proverka99 = regex_replace(proverka98, regex("Mmm"), "Mmn");
							string proverka100 = regex_replace(proverka99, regex("mmm"), "mmn");
							string proverka101 = regex_replace(proverka100, regex("mmM"), "mmN");
							string proverka102 = regex_replace(proverka101, regex("mMM"), "mMN");
							string proverka103 = regex_replace(proverka102, regex("mMm"), "mMn");
							string proverka104 = regex_replace(proverka103, regex("MmM"), "MmN");
							string proverka105 = regex_replace(proverka104, regex("NNN"), "NNO");
							string proverka106 = regex_replace(proverka105, regex("NNn"), "NNo");
							string proverka107 = regex_replace(proverka106, regex("Nnn"), "Nno");
							string proverka108 = regex_replace(proverka107, regex("nnn"), "nno");
							string proverka109 = regex_replace(proverka108, regex("nnN"), "nnO");
							string proverka110 = regex_replace(proverka109, regex("nNN"), "nNO");
							string proverka111 = regex_replace(proverka110, regex("nNn"), "nNo");
							string proverka112 = regex_replace(proverka111, regex("NnN"), "NnO");
							string proverka113 = regex_replace(proverka112, regex("OOO"), "OOP");
							string proverka114 = regex_replace(proverka113, regex("OOo"), "OOp");
							string proverka115 = regex_replace(proverka114, regex("Ooo"), "Oop");
							string proverka116 = regex_replace(proverka115, regex("ooo"), "oop");
							string proverka117 = regex_replace(proverka116, regex("ooO"), "ooP");
							string proverka118 = regex_replace(proverka117, regex("oOO"), "oOP");
							string proverka119 = regex_replace(proverka118, regex("oOo"), "oOp");
							string proverka120 = regex_replace(proverka119, regex("OoO"), "OoP");
							string proverka121 = regex_replace(proverka120, regex("PPP"), "PPQ");
							string proverka122 = regex_replace(proverka121, regex("PPp"), "PPq");
							string proverka123 = regex_replace(proverka122, regex("Ppp"), "Ppq");
							string proverka124 = regex_replace(proverka123, regex("ppp"), "ppq");
							string proverka125 = regex_replace(proverka124, regex("ppP"), "ppQ");
							string proverka126 = regex_replace(proverka125, regex("pPP"), "pPQ");
							string proverka127 = regex_replace(proverka126, regex("pPp"), "pPq");
							string proverka128 = regex_replace(proverka127, regex("PpP"), "PpQ");
							string proverka129 = regex_replace(proverka128, regex("QQQ"), "QQR");
							string proverka130 = regex_replace(proverka129, regex("QQq"), "QQr");
							string proverka131 = regex_replace(proverka130, regex("Qqq"), "Qqr");
							string proverka132 = regex_replace(proverka131, regex("qqq"), "qqr");
							string proverka133 = regex_replace(proverka132, regex("qqQ"), "qqR");
							string proverka134 = regex_replace(proverka133, regex("qQQ"), "qQR");
							string proverka135 = regex_replace(proverka134, regex("qQq"), "qQr");
							string proverka136 = regex_replace(proverka135, regex("QqQ"), "QqR");
							string proverka137 = regex_replace(proverka136, regex("RRR"), "RRS");
							string proverka138 = regex_replace(proverka137, regex("RRr"), "RRs");
							string proverka139 = regex_replace(proverka138, regex("Rrr"), "Rrs");
							string proverka140 = regex_replace(proverka139, regex("rrr"), "rrs");
							string proverka141 = regex_replace(proverka140, regex("rrR"), "rrS");
							string proverka142 = regex_replace(proverka141, regex("rRR"), "rRS");
							string proverka143 = regex_replace(proverka142, regex("rRr"), "rRs");
							string proverka144 = regex_replace(proverka143, regex("RrR"), "RrS");
							string proverka145 = regex_replace(proverka144, regex("SSS"), "SST");
							string proverka146 = regex_replace(proverka145, regex("SSs"), "SSt");
							string proverka147 = regex_replace(proverka146, regex("Sss"), "Sst");
							string proverka148 = regex_replace(proverka147, regex("sss"), "sst");
							string proverka149 = regex_replace(proverka148, regex("ssS"), "ssT");
							string proverka150 = regex_replace(proverka149, regex("sSS"), "sST");
							string proverka151 = regex_replace(proverka150, regex("sSs"), "sSt");
							string proverka152 = regex_replace(proverka151, regex("SsS"), "SsT");
							string proverka153 = regex_replace(proverka152, regex("TTT"), "TTU");
							string proverka154 = regex_replace(proverka153, regex("TTt"), "TTu");
							string proverka155 = regex_replace(proverka154, regex("Ttt"), "Ttu");
							string proverka156 = regex_replace(proverka155, regex("ttt"), "ttu");
							string proverka157 = regex_replace(proverka156, regex("ttT"), "ttU");
							string proverka158 = regex_replace(proverka157, regex("tTT"), "tTU");
							string proverka159 = regex_replace(proverka158, regex("tTt"), "tTu");
							string proverka160 = regex_replace(proverka159, regex("TtT"), "TtU");
							string proverka161 = regex_replace(proverka160, regex("UUU"), "UUV");
							string proverka162 = regex_replace(proverka161, regex("UUu"), "UUv");
							string proverka163 = regex_replace(proverka162, regex("Uuu"), "Uvv");
							string proverka164 = regex_replace(proverka163, regex("uuu"), "uuv");
							string proverka165 = regex_replace(proverka164, regex("uuU"), "uuV");
							string proverka166 = regex_replace(proverka165, regex("uUU"), "uUV");
							string proverka167 = regex_replace(proverka166, regex("uUu"), "uUv");
							string proverka168 = regex_replace(proverka167, regex("UuU"), "UuV");
							string proverka169 = regex_replace(proverka168, regex("VVV"), "VVW");
							string proverka170 = regex_replace(proverka169, regex("VVv"), "VVw");
							string proverka171 = regex_replace(proverka170, regex("Vvv"), "Vvw");
							string proverka172 = regex_replace(proverka171, regex("vvv"), "vvw");
							string proverka173 = regex_replace(proverka172, regex("vvV"), "vvW");
							string proverka174 = regex_replace(proverka173, regex("vVV"), "vVW");
							string proverka175 = regex_replace(proverka174, regex("vVv"), "vVw");
							string proverka176 = regex_replace(proverka175, regex("VvV"), "VvW");
							string proverka177 = regex_replace(proverka176, regex("WWW"), "WWX");
							string proverka178 = regex_replace(proverka177, regex("WWw"), "WWx");
							string proverka179 = regex_replace(proverka178, regex("Www"), "Wwx");
							string proverka180 = regex_replace(proverka179, regex("www"), "wwx");
							string proverka181 = regex_replace(proverka180, regex("wwW"), "wwX");
							string proverka182 = regex_replace(proverka181, regex("wWW"), "wWX");
							string proverka183 = regex_replace(proverka182, regex("wWw"), "wWx");
							string proverka184 = regex_replace(proverka183, regex("WwW"), "WwX");
							string proverka185 = regex_replace(proverka184, regex("XXX"), "XXY");
							string proverka186 = regex_replace(proverka185, regex("XXx"), "XXy");
							string proverka187 = regex_replace(proverka186, regex("Xxx"), "Xxy");
							string proverka188 = regex_replace(proverka187, regex("xxx"), "xxy");
							string proverka189 = regex_replace(proverka188, regex("xxX"), "xxY");
							string proverka190 = regex_replace(proverka189, regex("xXX"), "xXY");
							string proverka191 = regex_replace(proverka190, regex("xXx"), "xXy");
							string proverka192 = regex_replace(proverka191, regex("XxX"), "XxY");
							string proverka193 = regex_replace(proverka192, regex("YYY"), "YYZ");
							string proverka194 = regex_replace(proverka193, regex("YYy"), "YYz");
							string proverka195 = regex_replace(proverka194, regex("Yyy"), "Yyz");
							string proverka196 = regex_replace(proverka195, regex("yyy"), "yyz");
							string proverka197 = regex_replace(proverka196, regex("yyY"), "yyZ");
							string proverka198 = regex_replace(proverka197, regex("yYY"), "yYZ");
							string proverka199 = regex_replace(proverka198, regex("yYy"), "yYz");
							string proverka200 = regex_replace(proverka199, regex("YyY"), "YyZ");

							if (proverka200 != str) {
								zamena = "Filter 3 litters + Replace: " + str + " -> " + proverka200;
								//SetConsoleTitle(zamena.c_str());
								str = proverka200;
								counters2 += 1;
							}
						}
					}
				}
			}

			if (thId == 0) {
				str0 = str;
			}
			if (thId == 1) {
				str1 = str;
			}
			if (thId == 2) {
				str2 = str;
			}
			if (thId == 3) {
				str3 = str;
			}
			if (thId == 4) {
				str4 = str;
			}
			if (thId == 5) {
				str5 = str;
			}
			if (thId == 6) {
				str6 = str;
			}
			if (thId == 7) {
				str7 = str;
			}
			if (thId == 8) {
				str8 = str;
			}
			if (thId == 9) {
				str9 = str;
			}
			if (thId == 10) {
				str10 = str;
			}
			if (thId == 11) {
				str11 = str;
			}
			if (thId == 12) {
				str12 = str;
			}
			if (thId == 13) {
				str13 = str;
			}
			if (thId == 14) {
				str14 = str;
			}
			if (thId == 15) {
				str15 = str;
			}
			if (thId == 16) {
				str16 = str;
			}
			if (thId == 17) {
				str17 = str;
			}
			if (thId == 18) {
				str18 = str;
			}
			if (thId == 19) {
				str19 = str;
			}
			if (thId == 20) {
				str20 = str;
			}
			if (thId == 21) {
				str21 = str;
			}
			if (thId == 22) {
				str22 = str;
			}
			if (thId == 23) {
				str23 = str;
			}
			if (thId == 24) {
				str24 = str;
			}
			if (thId == 25) {
				str25 = str;
			}
			if (thId == 26) {
				str26 = str;
			}
			if (thId == 27) {
				str27 = str;
			}
			if (thId == 28) {
				str28 = str;
			}
			if (thId == 29) {
				str29 = str;
			}
			if (thId == 30) {
				str30 = str;
			}
			if (thId == 31) {
				str31 = str;
			}
			if (thId == 32) {
				str32 = str;
			}
			if (thId == 33) {
				str33 = str;
			}
			if (thId == 34) {
				str34 = str;
			}
			if (thId == 35) {
				str35 = str;
			}
			if (thId == 36) {
				str36 = str;
			}
			if (thId == 37) {
				str37 = str;
			}
			if (thId == 38) {
				str38 = str;
			}
			if (thId == 39) {
				str39 = str;
			}
			if (thId == 40) {
				str40 = str;
			}
			if (thId == 41) {
				str41 = str;
			}
			if (thId == 42) {
				str42 = str;
			}
			if (thId == 43) {
				str43 = str;
			}
			if (thId == 44) {
				str44 = str;
			}
			if (thId == 45) {
				str45 = str;
			}
			if (thId == 46) {
				str46 = str;
			}
			if (thId == 47) {
				str47 = str;
			}
			if (thId == 48) {
				str48 = str;
			}
			if (thId == 49) {
				str49 = str;
			}
			if (thId == 50) {
				str50 = str;
			}
			if (thId == 51) {
				str51 = str;
			}
			if (thId == 52) {
				str52 = str;
			}
			if (thId == 53) {
				str53 = str;
			}
			if (thId == 54) {
				str54 = str;
			}
			if (thId == 55) {
				str55 = str;
			}
			if (thId == 56) {
				str56 = str;
			}
			if (thId == 57) {
				str57 = str;
			}
			if (thId == 58) {
				str58 = str;
			}
			if (thId == 59) {
				str59 = str;
			}
			if (thId == 60) {
				str60 = str;
			}
			if (thId == 61) {
				str61 = str;
			}
			if (thId == 62) {
				str62 = str;
			}
			if (thId == 63) {
				str63 = str;
			}
			if (thId == 64) {
				str64 = str;
			}

			string input = str;
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);
			if (thId == 0) {
				input1 = str;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;

		} while (compare3(last, str));

	}
	if (rekey == 6) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;

		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment4(last);

			if (nbit > 4) {

				if (vremyax == nbit) {

					int asciiArray[256];
					char ch;
					int charconv;
					for (int i = 0; i < 256; i++)
						asciiArray[i] = 0;
					for (unsigned int i = 0; i < str.length(); i++)
					{
						ch = str[i];
						charconv = static_cast<int>(ch);
						asciiArray[charconv]++;
					}

					for (unsigned int i = 0; i < str.length(); i++)
					{
						char static alreadyprinted;
						char ch = str[i];

						if ((asciiArray[ch] > 2) && (ch != alreadyprinted) && (find(alreadyprintedcharacters.begin(), alreadyprintedcharacters.end(), ch) == alreadyprintedcharacters.end()))
						{
							string proverka = str;
							string proverka1 = regex_replace(proverka, regex("AAA"), "AAB");
							string proverka2 = regex_replace(proverka1, regex("AAa"), "AAb");
							string proverka3 = regex_replace(proverka2, regex("Aaa"), "Aab");
							string proverka4 = regex_replace(proverka3, regex("aaa"), "aab");
							string proverka5 = regex_replace(proverka4, regex("aaA"), "aaB");
							string proverka6 = regex_replace(proverka5, regex("aAA"), "aAB");
							string proverka7 = regex_replace(proverka6, regex("aAa"), "aAb");
							string proverka8 = regex_replace(proverka7, regex("AaA"), "AaB");
							string proverka9 = regex_replace(proverka8, regex("BBB"), "BBC");
							string proverka10 = regex_replace(proverka9, regex("BBb"), "BBc");
							string proverka11 = regex_replace(proverka10, regex("Bbb"), "Bbc");
							string proverka12 = regex_replace(proverka11, regex("bbb"), "bbc");
							string proverka13 = regex_replace(proverka12, regex("bbB"), "bbC");
							string proverka14 = regex_replace(proverka13, regex("bBB"), "bBC");
							string proverka15 = regex_replace(proverka14, regex("bBb"), "bBc");
							string proverka16 = regex_replace(proverka15, regex("BbB"), "BbC");
							string proverka17 = regex_replace(proverka16, regex("CCC"), "CCD");
							string proverka18 = regex_replace(proverka17, regex("CCc"), "CCd");
							string proverka19 = regex_replace(proverka18, regex("Ccc"), "Ccd");
							string proverka20 = regex_replace(proverka19, regex("ccc"), "ccd");
							string proverka21 = regex_replace(proverka20, regex("ccC"), "ccD");
							string proverka22 = regex_replace(proverka21, regex("cCC"), "cCD");
							string proverka23 = regex_replace(proverka22, regex("cCc"), "cCd");
							string proverka24 = regex_replace(proverka23, regex("CcC"), "CcD");
							string proverka25 = regex_replace(proverka24, regex("DDD"), "DDE");
							string proverka26 = regex_replace(proverka25, regex("DDd"), "DDe");
							string proverka27 = regex_replace(proverka26, regex("Ddd"), "Dde");
							string proverka28 = regex_replace(proverka27, regex("ddd"), "dde");
							string proverka29 = regex_replace(proverka28, regex("ddD"), "ddE");
							string proverka30 = regex_replace(proverka29, regex("dDD"), "dDE");
							string proverka31 = regex_replace(proverka30, regex("dDd"), "dDe");
							string proverka32 = regex_replace(proverka31, regex("DdD"), "DdE");
							string proverka33 = regex_replace(proverka32, regex("EEE"), "EEF");
							string proverka34 = regex_replace(proverka33, regex("EEe"), "EEf");
							string proverka35 = regex_replace(proverka34, regex("Eee"), "Eef");
							string proverka36 = regex_replace(proverka35, regex("eee"), "eef");
							string proverka37 = regex_replace(proverka36, regex("eeE"), "eeF");
							string proverka38 = regex_replace(proverka37, regex("eEE"), "eEF");
							string proverka39 = regex_replace(proverka38, regex("eEe"), "eEf");
							string proverka40 = regex_replace(proverka39, regex("EeE"), "EeF");
							string proverka41 = regex_replace(proverka40, regex("FFF"), "FFG");
							string proverka42 = regex_replace(proverka41, regex("FFf"), "FFg");
							string proverka43 = regex_replace(proverka42, regex("Fff"), "Ffg");
							string proverka44 = regex_replace(proverka43, regex("fff"), "ffg");
							string proverka45 = regex_replace(proverka44, regex("ffF"), "ffG");
							string proverka46 = regex_replace(proverka45, regex("fFF"), "fFG");
							string proverka47 = regex_replace(proverka46, regex("fFf"), "fFg");
							string proverka48 = regex_replace(proverka47, regex("FfF"), "FfG");
							string proverka49 = regex_replace(proverka48, regex("GGG"), "GGH");
							string proverka50 = regex_replace(proverka49, regex("GGg"), "GGh");
							string proverka51 = regex_replace(proverka50, regex("Ggg"), "Ggh");
							string proverka52 = regex_replace(proverka51, regex("ggg"), "ggh");
							string proverka53 = regex_replace(proverka52, regex("ggG"), "ggH");
							string proverka54 = regex_replace(proverka53, regex("gGG"), "gGH");
							string proverka55 = regex_replace(proverka54, regex("gGg"), "gGh");
							string proverka56 = regex_replace(proverka55, regex("GgG"), "GgH");
							string proverka57 = regex_replace(proverka56, regex("HHH"), "HHI");
							string proverka58 = regex_replace(proverka57, regex("HHh"), "HHi");
							string proverka59 = regex_replace(proverka58, regex("Hhh"), "Hhi");
							string proverka60 = regex_replace(proverka59, regex("hhh"), "hhi");
							string proverka61 = regex_replace(proverka60, regex("hhH"), "hhI");
							string proverka62 = regex_replace(proverka61, regex("hHH"), "hHI");
							string proverka63 = regex_replace(proverka62, regex("hHh"), "hHi");
							string proverka64 = regex_replace(proverka63, regex("HhH"), "HhI");
							string proverka65 = regex_replace(proverka64, regex("III"), "IIJ");
							string proverka66 = regex_replace(proverka65, regex("IIi"), "IIj");
							string proverka67 = regex_replace(proverka66, regex("Iii"), "Iij");
							string proverka68 = regex_replace(proverka67, regex("iii"), "iij");
							string proverka69 = regex_replace(proverka68, regex("iiI"), "iiJ");
							string proverka70 = regex_replace(proverka69, regex("iII"), "iIJ");
							string proverka71 = regex_replace(proverka70, regex("iIi"), "iIj");
							string proverka72 = regex_replace(proverka71, regex("IiI"), "IiJ");
							string proverka73 = regex_replace(proverka72, regex("JJJ"), "JJK");
							string proverka74 = regex_replace(proverka73, regex("JJj"), "JJk");
							string proverka75 = regex_replace(proverka74, regex("Jjj"), "Jjk");
							string proverka76 = regex_replace(proverka75, regex("jjj"), "jjk");
							string proverka77 = regex_replace(proverka76, regex("jjJ"), "jjK");
							string proverka78 = regex_replace(proverka77, regex("jJJ"), "jJK");
							string proverka79 = regex_replace(proverka78, regex("jJj"), "jJk");
							string proverka80 = regex_replace(proverka79, regex("JjJ"), "JjK");
							string proverka81 = regex_replace(proverka80, regex("KKK"), "KKL");
							string proverka82 = regex_replace(proverka81, regex("KKk"), "KKl");
							string proverka83 = regex_replace(proverka82, regex("Kkk"), "Kkl");
							string proverka84 = regex_replace(proverka83, regex("kkk"), "kkl");
							string proverka85 = regex_replace(proverka84, regex("kkK"), "kkL");
							string proverka86 = regex_replace(proverka85, regex("kKK"), "kKL");
							string proverka87 = regex_replace(proverka86, regex("kKk"), "kKl");
							string proverka88 = regex_replace(proverka87, regex("KkK"), "KkL");
							string proverka89 = regex_replace(proverka88, regex("LLL"), "LLM");
							string proverka90 = regex_replace(proverka89, regex("LLl"), "LLm");
							string proverka91 = regex_replace(proverka90, regex("Lll"), "Llm");
							string proverka92 = regex_replace(proverka91, regex("lll"), "llm");
							string proverka93 = regex_replace(proverka92, regex("llL"), "llM");
							string proverka94 = regex_replace(proverka93, regex("lLL"), "lLM");
							string proverka95 = regex_replace(proverka94, regex("lLl"), "lLm");
							string proverka96 = regex_replace(proverka95, regex("LlL"), "LlM");
							string proverka97 = regex_replace(proverka96, regex("MMM"), "MMN");
							string proverka98 = regex_replace(proverka97, regex("MMm"), "MMn");
							string proverka99 = regex_replace(proverka98, regex("Mmm"), "Mmn");
							string proverka100 = regex_replace(proverka99, regex("mmm"), "mmn");
							string proverka101 = regex_replace(proverka100, regex("mmM"), "mmN");
							string proverka102 = regex_replace(proverka101, regex("mMM"), "mMN");
							string proverka103 = regex_replace(proverka102, regex("mMm"), "mMn");
							string proverka104 = regex_replace(proverka103, regex("MmM"), "MmN");
							string proverka105 = regex_replace(proverka104, regex("NNN"), "NNO");
							string proverka106 = regex_replace(proverka105, regex("NNn"), "NNo");
							string proverka107 = regex_replace(proverka106, regex("Nnn"), "Nno");
							string proverka108 = regex_replace(proverka107, regex("nnn"), "nno");
							string proverka109 = regex_replace(proverka108, regex("nnN"), "nnO");
							string proverka110 = regex_replace(proverka109, regex("nNN"), "nNO");
							string proverka111 = regex_replace(proverka110, regex("nNn"), "nNo");
							string proverka112 = regex_replace(proverka111, regex("NnN"), "NnO");
							string proverka113 = regex_replace(proverka112, regex("OOO"), "OOP");
							string proverka114 = regex_replace(proverka113, regex("OOo"), "OOp");
							string proverka115 = regex_replace(proverka114, regex("Ooo"), "Oop");
							string proverka116 = regex_replace(proverka115, regex("ooo"), "oop");
							string proverka117 = regex_replace(proverka116, regex("ooO"), "ooP");
							string proverka118 = regex_replace(proverka117, regex("oOO"), "oOP");
							string proverka119 = regex_replace(proverka118, regex("oOo"), "oOp");
							string proverka120 = regex_replace(proverka119, regex("OoO"), "OoP");
							string proverka121 = regex_replace(proverka120, regex("PPP"), "PPQ");
							string proverka122 = regex_replace(proverka121, regex("PPp"), "PPq");
							string proverka123 = regex_replace(proverka122, regex("Ppp"), "Ppq");
							string proverka124 = regex_replace(proverka123, regex("ppp"), "ppq");
							string proverka125 = regex_replace(proverka124, regex("ppP"), "ppQ");
							string proverka126 = regex_replace(proverka125, regex("pPP"), "pPQ");
							string proverka127 = regex_replace(proverka126, regex("pPp"), "pPq");
							string proverka128 = regex_replace(proverka127, regex("PpP"), "PpQ");
							string proverka129 = regex_replace(proverka128, regex("QQQ"), "QQR");
							string proverka130 = regex_replace(proverka129, regex("QQq"), "QQr");
							string proverka131 = regex_replace(proverka130, regex("Qqq"), "Qqr");
							string proverka132 = regex_replace(proverka131, regex("qqq"), "qqr");
							string proverka133 = regex_replace(proverka132, regex("qqQ"), "qqR");
							string proverka134 = regex_replace(proverka133, regex("qQQ"), "qQR");
							string proverka135 = regex_replace(proverka134, regex("qQq"), "qQr");
							string proverka136 = regex_replace(proverka135, regex("QqQ"), "QqR");
							string proverka137 = regex_replace(proverka136, regex("RRR"), "RRS");
							string proverka138 = regex_replace(proverka137, regex("RRr"), "RRs");
							string proverka139 = regex_replace(proverka138, regex("Rrr"), "Rrs");
							string proverka140 = regex_replace(proverka139, regex("rrr"), "rrs");
							string proverka141 = regex_replace(proverka140, regex("rrR"), "rrS");
							string proverka142 = regex_replace(proverka141, regex("rRR"), "rRS");
							string proverka143 = regex_replace(proverka142, regex("rRr"), "rRs");
							string proverka144 = regex_replace(proverka143, regex("RrR"), "RrS");
							string proverka145 = regex_replace(proverka144, regex("SSS"), "SST");
							string proverka146 = regex_replace(proverka145, regex("SSs"), "SSt");
							string proverka147 = regex_replace(proverka146, regex("Sss"), "Sst");
							string proverka148 = regex_replace(proverka147, regex("sss"), "sst");
							string proverka149 = regex_replace(proverka148, regex("ssS"), "ssT");
							string proverka150 = regex_replace(proverka149, regex("sSS"), "sST");
							string proverka151 = regex_replace(proverka150, regex("sSs"), "sSt");
							string proverka152 = regex_replace(proverka151, regex("SsS"), "SsT");
							string proverka153 = regex_replace(proverka152, regex("TTT"), "TTU");
							string proverka154 = regex_replace(proverka153, regex("TTt"), "TTu");
							string proverka155 = regex_replace(proverka154, regex("Ttt"), "Ttu");
							string proverka156 = regex_replace(proverka155, regex("ttt"), "ttu");
							string proverka157 = regex_replace(proverka156, regex("ttT"), "ttU");
							string proverka158 = regex_replace(proverka157, regex("tTT"), "tTU");
							string proverka159 = regex_replace(proverka158, regex("tTt"), "tTu");
							string proverka160 = regex_replace(proverka159, regex("TtT"), "TtU");
							string proverka161 = regex_replace(proverka160, regex("UUU"), "UUV");
							string proverka162 = regex_replace(proverka161, regex("UUu"), "UUv");
							string proverka163 = regex_replace(proverka162, regex("Uuu"), "Uvv");
							string proverka164 = regex_replace(proverka163, regex("uuu"), "uuv");
							string proverka165 = regex_replace(proverka164, regex("uuU"), "uuV");
							string proverka166 = regex_replace(proverka165, regex("uUU"), "uUV");
							string proverka167 = regex_replace(proverka166, regex("uUu"), "uUv");
							string proverka168 = regex_replace(proverka167, regex("UuU"), "UuV");
							string proverka169 = regex_replace(proverka168, regex("VVV"), "VVW");
							string proverka170 = regex_replace(proverka169, regex("VVv"), "VVw");
							string proverka171 = regex_replace(proverka170, regex("Vvv"), "Vvw");
							string proverka172 = regex_replace(proverka171, regex("vvv"), "vvw");
							string proverka173 = regex_replace(proverka172, regex("vvV"), "vvW");
							string proverka174 = regex_replace(proverka173, regex("vVV"), "vVW");
							string proverka175 = regex_replace(proverka174, regex("vVv"), "vVw");
							string proverka176 = regex_replace(proverka175, regex("VvV"), "VvW");
							string proverka177 = regex_replace(proverka176, regex("WWW"), "WWX");
							string proverka178 = regex_replace(proverka177, regex("WWw"), "WWx");
							string proverka179 = regex_replace(proverka178, regex("Www"), "Wwx");
							string proverka180 = regex_replace(proverka179, regex("www"), "wwx");
							string proverka181 = regex_replace(proverka180, regex("wwW"), "wwX");
							string proverka182 = regex_replace(proverka181, regex("wWW"), "wWX");
							string proverka183 = regex_replace(proverka182, regex("wWw"), "wWx");
							string proverka184 = regex_replace(proverka183, regex("WwW"), "WwX");
							string proverka185 = regex_replace(proverka184, regex("XXX"), "XXY");
							string proverka186 = regex_replace(proverka185, regex("XXx"), "XXy");
							string proverka187 = regex_replace(proverka186, regex("Xxx"), "Xxy");
							string proverka188 = regex_replace(proverka187, regex("xxx"), "xxy");
							string proverka189 = regex_replace(proverka188, regex("xxX"), "xxY");
							string proverka190 = regex_replace(proverka189, regex("xXX"), "xXY");
							string proverka191 = regex_replace(proverka190, regex("xXx"), "xXy");
							string proverka192 = regex_replace(proverka191, regex("XxX"), "XxY");
							string proverka193 = regex_replace(proverka192, regex("YYY"), "YYZ");
							string proverka194 = regex_replace(proverka193, regex("YYy"), "YYz");
							string proverka195 = regex_replace(proverka194, regex("Yyy"), "Yyz");
							string proverka196 = regex_replace(proverka195, regex("yyy"), "yyz");
							string proverka197 = regex_replace(proverka196, regex("yyY"), "yyZ");
							string proverka198 = regex_replace(proverka197, regex("yYY"), "yYZ");
							string proverka199 = regex_replace(proverka198, regex("yYy"), "yYz");
							string proverka200 = regex_replace(proverka199, regex("YyY"), "YyZ");

							if (proverka200 != str) {
								zamena = "Filter 3 litters + Replace: " + str + " -> " + proverka200;
								//SetConsoleTitle(zamena.c_str());
								str = proverka200;
								counters2 += 1;
							}
						}
					}
				}
			}

			if (thId == 0) {
				str0 = str;
			}
			if (thId == 1) {
				str1 = str;
			}
			if (thId == 2) {
				str2 = str;
			}
			if (thId == 3) {
				str3 = str;
			}
			if (thId == 4) {
				str4 = str;
			}
			if (thId == 5) {
				str5 = str;
			}
			if (thId == 6) {
				str6 = str;
			}
			if (thId == 7) {
				str7 = str;
			}
			if (thId == 8) {
				str8 = str;
			}
			if (thId == 9) {
				str9 = str;
			}
			if (thId == 10) {
				str10 = str;
			}
			if (thId == 11) {
				str11 = str;
			}
			if (thId == 12) {
				str12 = str;
			}
			if (thId == 13) {
				str13 = str;
			}
			if (thId == 14) {
				str14 = str;
			}
			if (thId == 15) {
				str15 = str;
			}
			if (thId == 16) {
				str16 = str;
			}
			if (thId == 17) {
				str17 = str;
			}
			if (thId == 18) {
				str18 = str;
			}
			if (thId == 19) {
				str19 = str;
			}
			if (thId == 20) {
				str20 = str;
			}
			if (thId == 21) {
				str21 = str;
			}
			if (thId == 22) {
				str22 = str;
			}
			if (thId == 23) {
				str23 = str;
			}
			if (thId == 24) {
				str24 = str;
			}
			if (thId == 25) {
				str25 = str;
			}
			if (thId == 26) {
				str26 = str;
			}
			if (thId == 27) {
				str27 = str;
			}
			if (thId == 28) {
				str28 = str;
			}
			if (thId == 29) {
				str29 = str;
			}
			if (thId == 30) {
				str30 = str;
			}
			if (thId == 31) {
				str31 = str;
			}
			if (thId == 32) {
				str32 = str;
			}
			if (thId == 33) {
				str33 = str;
			}
			if (thId == 34) {
				str34 = str;
			}
			if (thId == 35) {
				str35 = str;
			}
			if (thId == 36) {
				str36 = str;
			}
			if (thId == 37) {
				str37 = str;
			}
			if (thId == 38) {
				str38 = str;
			}
			if (thId == 39) {
				str39 = str;
			}
			if (thId == 40) {
				str40 = str;
			}
			if (thId == 41) {
				str41 = str;
			}
			if (thId == 42) {
				str42 = str;
			}
			if (thId == 43) {
				str43 = str;
			}
			if (thId == 44) {
				str44 = str;
			}
			if (thId == 45) {
				str45 = str;
			}
			if (thId == 46) {
				str46 = str;
			}
			if (thId == 47) {
				str47 = str;
			}
			if (thId == 48) {
				str48 = str;
			}
			if (thId == 49) {
				str49 = str;
			}
			if (thId == 50) {
				str50 = str;
			}
			if (thId == 51) {
				str51 = str;
			}
			if (thId == 52) {
				str52 = str;
			}
			if (thId == 53) {
				str53 = str;
			}
			if (thId == 54) {
				str54 = str;
			}
			if (thId == 55) {
				str55 = str;
			}
			if (thId == 56) {
				str56 = str;
			}
			if (thId == 57) {
				str57 = str;
			}
			if (thId == 58) {
				str58 = str;
			}
			if (thId == 59) {
				str59 = str;
			}
			if (thId == 60) {
				str60 = str;
			}
			if (thId == 61) {
				str61 = str;
			}
			if (thId == 62) {
				str62 = str;
			}
			if (thId == 63) {
				str63 = str;
			}
			if (thId == 64) {
				str64 = str;
			}

			string input = str;
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);
			if (thId == 0) {
				input1 = str;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;

		} while (compare4(last, str));

	}
	if (rekey == 7) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;
		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment(last);
			string input = str;

			if (thId == 0) {

				str0 = str;
				std::stringstream ss;
				ss << str << kstr0;
				std::string priv = ss.str();

				bool isComp;
				key0 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				key.Set(&key0);
				kisa0.Set(&key0);
				input1 = priv;
				input2 = key;

				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 1) {
				str1 = str;
				std::stringstream ss;
				ss << str << kstr1;
				std::string priv = ss.str();

				bool isComp;
				key1 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				key.Set(&key1);
				kisa1.Set(&key1);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 2) {

				str2 = str;
				std::stringstream ss;
				ss << str << kstr2;
				std::string priv = ss.str();

				bool isComp;
				key2 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key2);
				kisa2.Set(&key2);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 3) {

				str3 = str;
				std::stringstream ss;
				ss << str << kstr3;
				std::string priv = ss.str();

				bool isComp;
				key3 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key3);
				kisa3.Set(&key3);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 4) {

				str4 = str;
				std::stringstream ss;
				ss << str << kstr4;
				std::string priv = ss.str();

				bool isComp;
				key4 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key4);
				kisa4.Set(&key4);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 5) {

				str5 = str;
				std::stringstream ss;
				ss << str << kstr5;
				std::string priv = ss.str();

				bool isComp;
				key5 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key5);
				kisa5.Set(&key5);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 6) {

				str6 = str;
				std::stringstream ss;
				ss << str << kstr6;
				std::string priv = ss.str();

				bool isComp;
				key6 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key6);
				kisa6.Set(&key6);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 7) {

				str7 = str;
				std::stringstream ss;
				ss << str << kstr7;
				std::string priv = ss.str();

				bool isComp;
				key7 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key7);
				kisa7.Set(&key7);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 8) {

				str8 = str;
				std::stringstream ss;
				ss << str << kstr8;
				std::string priv = ss.str();

				bool isComp;
				key8 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key8);
				kisa8.Set(&key8);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 9) {

				str9 = str;
				std::stringstream ss;
				ss << str << kstr9;
				std::string priv = ss.str();

				bool isComp;
				key9 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key9);
				kisa9.Set(&key9);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 10) {

				str10 = str;
				std::stringstream ss;
				ss << str << kstr10;
				std::string priv = ss.str();

				bool isComp;
				key10 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key10);
				kisa10.Set(&key10);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 11) {

				str11 = str;
				std::stringstream ss;
				ss << str << kstr11;
				std::string priv = ss.str();

				bool isComp;
				key11 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key11);
				kisa11.Set(&key11);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 12) {

				str12 = str;
				std::stringstream ss;
				ss << str << kstr12;
				std::string priv = ss.str();

				bool isComp;
				key12 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key12);
				kisa12.Set(&key12);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 13) {

				str13 = str;
				std::stringstream ss;
				ss << str << kstr13;
				std::string priv = ss.str();

				bool isComp;
				key13 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key13);
				kisa13.Set(&key13);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 14) {

				str14 = str;
				std::stringstream ss;
				ss << str << kstr14;
				std::string priv = ss.str();

				bool isComp;
				key14 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key14);
				kisa14.Set(&key14);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 15) {

				str15 = str;
				std::stringstream ss;
				ss << str << kstr15;
				std::string priv = ss.str();

				bool isComp;
				key15 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key15);
				kisa15.Set(&key15);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 16) {

				str16 = str;
				std::stringstream ss;
				ss << str << kstr16;
				std::string priv = ss.str();

				bool isComp;
				key16 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key16);
				kisa16.Set(&key16);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 17) {

				str17 = str;
				std::stringstream ss;
				ss << str << kstr17;
				std::string priv = ss.str();

				bool isComp;
				key17 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key17);
				kisa17.Set(&key17);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 18) {

				str18 = str;
				std::stringstream ss;
				ss << str << kstr18;
				std::string priv = ss.str();

				bool isComp;
				key18 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key18);
				kisa18.Set(&key18);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 19) {

				str19 = str;
				std::stringstream ss;
				ss << str << kstr19;
				std::string priv = ss.str();

				bool isComp;
				key19 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key19);
				kisa19.Set(&key19);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 20) {

				str20 = str;
				std::stringstream ss;
				ss << str << kstr20;
				std::string priv = ss.str();

				bool isComp;
				key20 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key20);
				kisa20.Set(&key20);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 21) {

				str21 = str;
				std::stringstream ss;
				ss << str << kstr21;
				std::string priv = ss.str();

				bool isComp;
				key21 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key21);
				kisa21.Set(&key21);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 22) {

				str22 = str;
				std::stringstream ss;
				ss << str << kstr22;
				std::string priv = ss.str();

				bool isComp;
				key22 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key22);
				kisa22.Set(&key22);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 23) {

				str23 = str;
				std::stringstream ss;
				ss << str << kstr23;
				std::string priv = ss.str();

				bool isComp;
				key23 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key23);
				kisa23.Set(&key23);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 24) {

				str24 = str;
				std::stringstream ss;
				ss << str << kstr24;
				std::string priv = ss.str();

				bool isComp;
				key24 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key24);
				kisa24.Set(&key24);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 25) {

				str25 = str;
				std::stringstream ss;
				ss << str << kstr25;
				std::string priv = ss.str();

				bool isComp;
				key25 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key25);
				kisa25.Set(&key25);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 26) {

				str26 = str;
				std::stringstream ss;
				ss << str << kstr26;
				std::string priv = ss.str();

				bool isComp;
				key26 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key26);
				kisa26.Set(&key26);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 27) {

				str27 = str;
				std::stringstream ss;
				ss << str << kstr27;
				std::string priv = ss.str();

				bool isComp;
				key27 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key27);
				kisa27.Set(&key27);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 28) {

				str28 = str;
				std::stringstream ss;
				ss << str << kstr28;
				std::string priv = ss.str();

				bool isComp;
				key28 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);


				key.Set(&key28);
				kisa28.Set(&key28);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 29) {

				str29 = str;
				std::stringstream ss;
				ss << str << kstr29;
				std::string priv = ss.str();

				bool isComp;
				key29 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key29);
				kisa29.Set(&key29);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 30) {

				str30 = str;
				std::stringstream ss;
				ss << str << kstr30;
				std::string priv = ss.str();

				bool isComp;
				key30 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key30);
				kisa30.Set(&key30);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 31) {
				str31 = str;
				std::stringstream ss;
				ss << str << kstr31;
				std::string priv = ss.str();

				bool isComp;
				key31 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key31);
				kisa31.Set(&key31);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 32) {

				str32 = str;
				std::stringstream ss;
				ss << str << kstr32;
				std::string priv = ss.str();

				bool isComp;
				key32 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key32);
				kisa32.Set(&key32);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 33) {

				str33 = str;
				std::stringstream ss;
				ss << str << kstr33;
				std::string priv = ss.str();

				bool isComp;
				key33 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key33);
				kisa33.Set(&key33);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 34) {

				str34 = str;
				std::stringstream ss;
				ss << str << kstr34;
				std::string priv = ss.str();

				bool isComp;
				key34 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key34);
				kisa34.Set(&key34);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 35) {

				str35 = str;
				std::stringstream ss;
				ss << str << kstr35;
				std::string priv = ss.str();

				bool isComp;
				key35 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key35);
				kisa35.Set(&key35);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 36) {
				str36 = str;
				std::stringstream ss;
				ss << str << kstr36;
				std::string priv = ss.str();

				bool isComp;
				key36 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key36);
				kisa36.Set(&key36);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 37) {

				str37 = str;
				std::stringstream ss;
				ss << str << kstr37;
				std::string priv = ss.str();

				bool isComp;
				key37 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key37);
				kisa37.Set(&key37);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 38) {

				str38 = str;
				std::stringstream ss;
				ss << str << kstr38;
				std::string priv = ss.str();

				bool isComp;
				key38 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key38);
				kisa38.Set(&key38);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 39) {

				str39 = str;
				std::stringstream ss;
				ss << str << kstr39;
				std::string priv = ss.str();

				bool isComp;
				key39 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key39);
				kisa39.Set(&key39);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 40) {

				str40 = str;
				std::stringstream ss;
				ss << str << kstr40;
				std::string priv = ss.str();

				bool isComp;
				key40 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key40);
				kisa40.Set(&key40);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 41) {

				str41 = str;
				std::stringstream ss;
				ss << str << kstr41;
				std::string priv = ss.str();

				bool isComp;
				key41 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key41);
				kisa41.Set(&key41);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 42) {
				str42 = str;
				std::stringstream ss;
				ss << str << kstr42;
				std::string priv = ss.str();

				bool isComp;
				key42 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key42);
				kisa42.Set(&key42);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 43) {
				str43 = str;
				std::stringstream ss;
				ss << str << kstr43;
				std::string priv = ss.str();

				bool isComp;
				key43 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key43);
				kisa43.Set(&key43);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 44) {

				str44 = str;
				std::stringstream ss;
				ss << str << kstr44;
				std::string priv = ss.str();

				bool isComp;
				key44 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key44);
				kisa44.Set(&key44);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 45) {

				str45 = str;
				std::stringstream ss;
				ss << str << kstr45;
				std::string priv = ss.str();

				bool isComp;
				key45 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key45);
				kisa45.Set(&key45);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 46) {

				str46 = str;
				std::stringstream ss;
				ss << str << kstr46;
				std::string priv = ss.str();

				bool isComp;
				key46 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key46);
				kisa46.Set(&key46);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 47) {

				str47 = str;
				std::stringstream ss;
				ss << str << kstr47;
				std::string priv = ss.str();

				bool isComp;
				key47 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key47);
				kisa47.Set(&key47);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 48) {

				str48 = str;
				std::stringstream ss;
				ss << str << kstr48;
				std::string priv = ss.str();

				bool isComp;
				key48 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key48);
				kisa48.Set(&key48);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 49) {

				str49 = str;
				std::stringstream ss;
				ss << str << kstr49;
				std::string priv = ss.str();

				bool isComp;
				key49 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key49);
				kisa49.Set(&key49);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 50) {

				str50 = str;
				std::stringstream ss;
				ss << str << kstr50;
				std::string priv = ss.str();

				bool isComp;
				key50 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key50);
				kisa50.Set(&key50);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 51) {

				str51 = str;
				std::stringstream ss;
				ss << str << kstr51;
				std::string priv = ss.str();

				bool isComp;
				key51 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key51);
				kisa51.Set(&key51);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 52) {
				str52 = str;
				std::stringstream ss;
				ss << str << kstr52;
				std::string priv = ss.str();

				bool isComp;
				key52 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key52);
				kisa52.Set(&key52);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 53) {

				str53 = str;
				std::stringstream ss;
				ss << str << kstr53;
				std::string priv = ss.str();

				bool isComp;
				key53 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key53);
				kisa53.Set(&key53);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 54) {

				str54 = str;
				std::stringstream ss;
				ss << str << kstr54;
				std::string priv = ss.str();

				bool isComp;
				key54 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key54);
				kisa54.Set(&key54);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 55) {

				str55 = str;
				std::stringstream ss;
				ss << str << kstr55;
				std::string priv = ss.str();

				bool isComp;
				key55 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key55);
				kisa55.Set(&key55);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}

			if (thId == 56) {

				str56 = str;
				std::stringstream ss;
				ss << str << kstr56;
				std::string priv = ss.str();

				bool isComp;
				key56 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key56);
				kisa56.Set(&key56);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 57) {

				str57 = str;
				std::stringstream ss;
				ss << str << kstr57;
				std::string priv = ss.str();

				bool isComp;
				key57 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key57);
				kisa57.Set(&key57);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 58) {

				str58 = str;
				std::stringstream ss;
				ss << str << kstr58;
				std::string priv = ss.str();

				bool isComp;
				key58 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key58);
				kisa58.Set(&key58);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 59) {

				str59 = str;
				std::stringstream ss;
				ss << str << kstr59;
				std::string priv = ss.str();

				bool isComp;
				key59 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key59);
				kisa59.Set(&key59);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 60) {

				str60 = str;
				std::stringstream ss;
				ss << str << kstr60;
				std::string priv = ss.str();

				bool isComp;
				key60 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key60);
				kisa60.Set(&key60);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 61) {

				str61 = str;
				std::stringstream ss;
				ss << str << kstr61;
				std::string priv = ss.str();

				bool isComp;
				key61 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key61);
				kisa61.Set(&key61);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 62) {

				str62 = str;
				std::stringstream ss;
				ss << str << kstr62;
				std::string priv = ss.str();

				bool isComp;
				key62 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key62);
				kisa62.Set(&key62);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 63) {

				str63 = str;
				std::stringstream ss;
				ss << str << kstr63;
				std::string priv = ss.str();

				bool isComp;
				key63 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key63);
				kisa63.Set(&key63);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}
			if (thId == 64) {

				str64 = str;
				std::stringstream ss;
				ss << str << kstr64;
				std::string priv = ss.str();

				bool isComp;
				key64 = secp->DecodePrivateKey((char*)priv.c_str(), &isComp);

				key.Set(&key64);
				kisa64.Set(&key64);
				startP = secp->ComputePublicKey(&key);
				int i = 0;
				if (coinType == COIN_BTC) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, startP);
							checkMultiAddresses(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, startP);
							checkSingleAddress(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, startP);
							checkMultiXPoints(false, key, i, startP);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, startP);
							checkSingleXPoint(false, key, i, startP);
							break;
						default:
							break;
						}
						break;
					}
				}
				else {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, startP);
						break;
					default:
						break;
					}
				}
				counters[thId] += 1;
			}

		} while (compare(last, str));
	}
	if (rekey == 8) {

		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;

		if (thId == 0) {
			initial = str0;
		}
		if (thId == 1) {
			initial = str1;
		}
		if (thId == 2) {
			initial = str2;
		}
		if (thId == 3) {
			initial = str3;
		}
		if (thId == 4) {
			initial = str4;
		}
		if (thId == 5) {
			initial = str5;
		}
		if (thId == 6) {
			initial = str6;
		}
		if (thId == 7) {
			initial = str7;
		}
		if (thId == 8) {
			initial = str8;
		}
		if (thId == 9) {
			initial = str9;
		}
		if (thId == 10) {
			initial = str10;
		}
		if (thId == 11) {
			initial = str11;
		}
		if (thId == 12) {
			initial = str12;
		}
		if (thId == 13) {
			initial = str13;
		}
		if (thId == 14) {
			initial = str14;
		}
		if (thId == 15) {
			initial = str15;
		}
		if (thId == 16) {
			initial = str16;
		}
		if (thId == 17) {
			initial = str17;
		}
		if (thId == 18) {
			initial = str18;
		}
		if (thId == 19) {
			initial = str19;
		}
		if (thId == 20) {
			initial = str20;
		}
		if (thId == 21) {
			initial = str21;
		}
		if (thId == 22) {
			initial = str22;
		}
		if (thId == 23) {
			initial = str23;
		}
		if (thId == 24) {
			initial = str24;
		}
		if (thId == 25) {
			initial = str25;
		}
		if (thId == 26) {
			initial = str26;
		}
		if (thId == 27) {
			initial = str27;
		}
		if (thId == 28) {
			initial = str28;
		}
		if (thId == 29) {
			initial = str29;
		}
		if (thId == 30) {
			initial = str30;
		}
		if (thId == 31) {
			initial = str31;
		}
		if (thId == 32) {
			initial = str32;
		}
		if (thId == 33) {
			initial = str33;
		}
		if (thId == 34) {
			initial = str34;
		}
		if (thId == 35) {
			initial = str35;
		}
		if (thId == 36) {
			initial = str36;
		}
		if (thId == 37) {
			initial = str37;
		}
		if (thId == 38) {
			initial = str38;
		}
		if (thId == 39) {
			initial = str39;
		}
		if (thId == 40) {
			initial = str40;
		}
		if (thId == 41) {
			initial = str41;
		}
		if (thId == 42) {
			initial = str42;
		}
		if (thId == 43) {
			initial = str43;
		}
		if (thId == 44) {
			initial = str44;
		}
		if (thId == 45) {
			initial = str45;
		}
		if (thId == 46) {
			initial = str46;
		}
		if (thId == 47) {
			initial = str47;
		}
		if (thId == 48) {
			initial = str48;
		}
		if (thId == 49) {
			initial = str49;
		}
		if (thId == 50) {
			initial = str50;
		}
		if (thId == 51) {
			initial = str51;
		}
		if (thId == 52) {
			initial = str52;
		}
		if (thId == 53) {
			initial = str53;
		}
		if (thId == 54) {
			initial = str54;
		}
		if (thId == 55) {
			initial = str55;
		}
		if (thId == 56) {
			initial = str56;
		}
		if (thId == 57) {
			initial = str57;
		}
		if (thId == 58) {
			initial = str58;
		}
		if (thId == 59) {
			initial = str59;
		}
		if (thId == 60) {
			initial = str60;
		}
		if (thId == 61) {
			initial = str61;
		}
		if (thId == 62) {
			initial = str62;
		}
		if (thId == 63) {
			initial = str63;
		}
		if (thId == 64) {
			initial = str64;
		}

		string str = initial;
		string last;
		do {
			last = str;
			str = increment(last);

			if (thId == 0) {
				str0 = str;
			}
			if (thId == 1) {
				str1 = str;
			}
			if (thId == 2) {
				str2 = str;
			}
			if (thId == 3) {
				str3 = str;
			}
			if (thId == 4) {
				str4 = str;
			}
			if (thId == 5) {
				str5 = str;
			}
			if (thId == 6) {
				str6 = str;
			}
			if (thId == 7) {
				str7 = str;
			}
			if (thId == 8) {
				str8 = str;
			}
			if (thId == 9) {
				str9 = str;
			}
			if (thId == 10) {
				str10 = str;
			}
			if (thId == 11) {
				str11 = str;
			}
			if (thId == 12) {
				str12 = str;
			}
			if (thId == 13) {
				str13 = str;
			}
			if (thId == 14) {
				str14 = str;
			}
			if (thId == 15) {
				str15 = str;
			}
			if (thId == 16) {
				str16 = str;
			}
			if (thId == 17) {
				str17 = str;
			}
			if (thId == 18) {
				str18 = str;
			}
			if (thId == 19) {
				str19 = str;
			}
			if (thId == 20) {
				str20 = str;
			}
			if (thId == 21) {
				str21 = str;
			}
			if (thId == 22) {
				str22 = str;
			}
			if (thId == 23) {
				str23 = str;
			}
			if (thId == 24) {
				str24 = str;
			}
			if (thId == 25) {
				str25 = str;
			}
			if (thId == 26) {
				str26 = str;
			}
			if (thId == 27) {
				str27 = str;
			}
			if (thId == 28) {
				str28 = str;
			}
			if (thId == 29) {
				str29 = str;
			}
			if (thId == 30) {
				str30 = str;
			}
			if (thId == 31) {
				str31 = str;
			}
			if (thId == 32) {
				str32 = str;
			}
			if (thId == 33) {
				str33 = str;
			}
			if (thId == 34) {
				str34 = str;
			}
			if (thId == 35) {
				str35 = str;
			}
			if (thId == 36) {
				str36 = str;
			}
			if (thId == 37) {
				str37 = str;
			}
			if (thId == 38) {
				str38 = str;
			}
			if (thId == 39) {
				str39 = str;
			}
			if (thId == 40) {
				str40 = str;
			}
			if (thId == 41) {
				str41 = str;
			}
			if (thId == 42) {
				str42 = str;
			}
			if (thId == 43) {
				str43 = str;
			}
			if (thId == 44) {
				str44 = str;
			}
			if (thId == 45) {
				str45 = str;
			}
			if (thId == 46) {
				str46 = str;
			}
			if (thId == 47) {
				str47 = str;
			}
			if (thId == 48) {
				str48 = str;
			}
			if (thId == 49) {
				str49 = str;
			}
			if (thId == 50) {
				str50 = str;
			}
			if (thId == 51) {
				str51 = str;
			}
			if (thId == 52) {
				str52 = str;
			}
			if (thId == 53) {
				str53 = str;
			}
			if (thId == 54) {
				str54 = str;
			}
			if (thId == 55) {
				str55 = str;
			}
			if (thId == 56) {
				str56 = str;
			}
			if (thId == 57) {
				str57 = str;
			}
			if (thId == 58) {
				str58 = str;
			}
			if (thId == 59) {
				str59 = str;
			}
			if (thId == 60) {
				str60 = str;
			}
			if (thId == 61) {
				str61 = str;
			}
			if (thId == 62) {
				str62 = str;
			}
			if (thId == 63) {
				str63 = str;
			}
			if (thId == 64) {
				str64 = str;
			}

			string input = str;
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);
			if (thId == 0) {
				input1 = str;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;

		} while (compare(last, str));

	}
	
	if (rekey == 10) {
		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		string initial;
		ph->hasStarted = true;
		ph->rKeyRequest = false;
		
		while (1 < 2) {

			int N = 21;
			char str[]{ "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789" };
			int strN = 58;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << "S" << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);

			if (thId == 0) {
				input1 = input;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;
			delete[] pass;
		}

	}
	
	
	if (rekey == 11) {
		int thId = ph->threadId;
		counters[thId] = 0;

		Int  key;
		Point startP;

		ph->hasStarted = true;
		ph->rKeyRequest = false;
		while (1 < 2) {

			int N = 29;
			char str[]{ "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789" };
			int strN = 58;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			
			std::stringstream ss;
			ss << "S" << pass;
			std::string nkkr = ss.str();
			
			string nos = sha256(nkkr);
			char* cstr = &nos[0];
			key.SetBase16(cstr);

			if (thId == 0) {
				input1 = nkkr;
				input2 = key;
			}
			startP = secp->ComputePublicKey(&key);
			int i = 0;
			if (coinType == COIN_BTC) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_UNCOMPRESSED:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				case SEARCH_BOTH:
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddresses(true, key, i, startP);
						checkMultiAddresses(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddress(true, key, i, startP);
						checkSingleAddress(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_MX:
						checkMultiXPoints(true, key, i, startP);
						checkMultiXPoints(false, key, i, startP);
						break;
					case (int)SEARCH_MODE_SX:
						checkSingleXPoint(true, key, i, startP);
						checkSingleXPoint(false, key, i, startP);
						break;
					default:
						break;
					}
					break;
				}
			}
			else {
				switch (searchMode) {
				case (int)SEARCH_MODE_MA:
					checkMultiAddressesETH(key, i, startP);
					break;
				case (int)SEARCH_MODE_SA:
					checkSingleAddressETH(key, i, startP);
					break;
				default:
					break;
				}
			}
			counters[thId] += 1;
			delete[] pass;
		}
	}
}

// ----------------------------------------------------------------------------

void Fialka::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{
	ifstream file7777("WIF.txt");
	string s7777;
	for (int i = 0; i < nbThread; i++) {
		getline(file7777, s7777);
		bool isComp;
		key0 = secp->DecodePrivateKey((char*)s7777.c_str(), &isComp);
		if (i == 0) {
			input1 = s7777;
			input2 = key0;
		}
		keys[i].Set(&key0);
		Int k(keys + i);
		k.Add((uint64_t)(groupSize / 2));
		p[i] = secp->ComputePublicKey(&k);
	}

	file7777.close();
}

void Fialka::FindKeyGPU(TH_PARAM* ph)
{

	bool ok = true;

#ifdef WITHGPU

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g;
	switch (searchMode) {
	case (int)SEARCH_MODE_MA:
	case (int)SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SA:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			hash160Keccak, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			xpoint, (rKey != 0));
		break;
	default:
		printf("  Invalid search mode format!");
		return;
		break;
	}


	int nbThread = g->GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;

	printf("  GPU          : %s\n", g->deviceName.c_str());

	counters[thId] = 0;

	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
	ok = g->SetKeys(p);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	// GPU Thread
	while (ok && !endOfSearch) {

		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
			ok = g->SetKeys(p);
			ph->rKeyRequest = false;
		}

		// Call kernel
		switch (searchMode) {
		case (int)SEARCH_MODE_MA:
			ok = g->LaunchSEARCH_MODE_MA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_MX:
			ok = g->LaunchSEARCH_MODE_MX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				//Point pk;
				//memcpy((uint32_t*)pk.x.bits, (uint32_t*)it.hash, 8);
				//string addr = secp->GetAddress(it.mode, pk);
				if (checkPrivKeyX(/*addr,*/ keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		case (int)SEARCH_MODE_SA:
			ok = g->LaunchSEARCH_MODE_SA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_SX:
			ok = g->LaunchSEARCH_MODE_SX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				//Point pk;
				//memcpy((uint32_t*)pk.x.bits, (uint32_t*)it.hash, 8);
				//string addr = secp->GetAddress(it.mode, pk);
				if (checkPrivKeyX(/*addr,*/ keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		default:
			break;
		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // Point
		}

	}

	//delete[] keys;
	delete[] p;
	delete g;

#else
	ph->hasStarted = true;
	printf("  GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;

}

// ----------------------------------------------------------------------------

bool Fialka::isAlive(TH_PARAM * p)
{

	bool isAlive = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		isAlive = isAlive && p[i].isRunning;

	return isAlive;

}

// ----------------------------------------------------------------------------

bool Fialka::hasStarted(TH_PARAM * p)
{
	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;

	return hasStarted;

}

// ----------------------------------------------------------------------------

uint64_t Fialka::getGPUCount()
{
	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;

}

// ----------------------------------------------------------------------------

uint64_t Fialka::getCPUCount()
{

	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;

}

// ----------------------------------------------------------------------------

void Fialka::rKeyRequest(TH_PARAM * p) {

	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rKeyRequest = true;

}
// ----------------------------------------------------------------------------

void Fialka::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

// ----------------------------------------------------------------------------

void Fialka::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{

	double t0;
	double t1;
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	// setup ranges
	SetupRanges(nbCPUThread + nbGPUThread);

	memset(counters, 0, sizeof(counters));

	if (!useGpu)
		printf("\n");

	TH_PARAM* params = (TH_PARAM*)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;
		if (rKey > 0) {
			Int kubik;
			params[i].rangeStart.Set(&kubik);
		}
		else {
			params[i].rangeStart.Set(&rangeStart);
			rangeStart.Add(&rangeDiff);
			params[i].rangeEnd.Set(&rangeStart);
		}
		

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyCPU, (void*)(params + i), 0, &thread_id);
		ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyCPU, (void*)(params + i));
		ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[nbCPUThread + i].obj = this;
		params[nbCPUThread + i].threadId = 0x80L + i;
		params[nbCPUThread + i].isRunning = true;
		params[nbCPUThread + i].gpuId = gpuId[i];
		params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
		params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];
		if (rKey > 0) {
			Int kubik;
			params[nbCPUThread + i].rangeStart.Set(&kubik);
		}
		else {
			params[nbCPUThread + i].rangeStart.Set(&rangeStart);
			rangeStart.Add(&rangeDiff);
			params[nbCPUThread + i].rangeEnd.Set(&rangeStart);
		}
		


#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + (nbCPUThread + i)), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (nbCPUThread + i)));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount;
	p100.SetInt32(100);
	double completedPerc = 0;
	uint64_t rKeyCount = 0;
	while (isAlive(params)) {

		int delay = 1000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}

		gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();
		if (rKey <= 0) {
			completedPerc = CalcPercantage(ICount, rangeStart, rangeDiff2);
			//ICount.Mult(&p100);
			//ICount.Div(&this->rangeDiff2);
			//completedPerc = std::stoi(ICount.GetBase10());
		}
		minuty++;

		if (rekey == 3) {

			if (minuty == 300) {

				char* ctimeBuff;
				time_t now = time(NULL);
				ctimeBuff = ctime(&now);

				if (nbit2 < 13) {

					if (nbit == 0) {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s\n", str0.c_str());
						fprintf(ptrFile, "%s\n", str1.c_str());
						fprintf(ptrFile, "%s\n", str2.c_str());
						fprintf(ptrFile, "%s\n", str3.c_str());
						fprintf(ptrFile, "%s\n", str4.c_str());
						fprintf(ptrFile, "%s\n", str5.c_str());
						fprintf(ptrFile, "%s\n", str6.c_str());
						fprintf(ptrFile, "%s\n", str7.c_str());
						fprintf(ptrFile, "%s\n", str8.c_str());
						fprintf(ptrFile, "%s\n", str9.c_str());
						fprintf(ptrFile, "%s\n", str10.c_str());
						fprintf(ptrFile, "%s\n", str11.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
					else {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s%s\n", str0.c_str(), kstr0.c_str());
						fprintf(ptrFile, "%s%s\n", str1.c_str(), kstr1.c_str());
						fprintf(ptrFile, "%s%s\n", str2.c_str(), kstr2.c_str());
						fprintf(ptrFile, "%s%s\n", str3.c_str(), kstr3.c_str());
						fprintf(ptrFile, "%s%s\n", str4.c_str(), kstr4.c_str());
						fprintf(ptrFile, "%s%s\n", str5.c_str(), kstr5.c_str());
						fprintf(ptrFile, "%s%s\n", str6.c_str(), kstr6.c_str());
						fprintf(ptrFile, "%s%s\n", str7.c_str(), kstr7.c_str());
						fprintf(ptrFile, "%s%s\n", str8.c_str(), kstr8.c_str());
						fprintf(ptrFile, "%s%s\n", str9.c_str(), kstr9.c_str());
						fprintf(ptrFile, "%s%s\n", str10.c_str(), kstr10.c_str());
						fprintf(ptrFile, "%s%s\n", str11.c_str(), kstr11.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
				}
				else {
					if (nbit == 0) {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s\n", str0.c_str());
						fprintf(ptrFile, "%s\n", str1.c_str());
						fprintf(ptrFile, "%s\n", str2.c_str());
						fprintf(ptrFile, "%s\n", str3.c_str());
						fprintf(ptrFile, "%s\n", str4.c_str());
						fprintf(ptrFile, "%s\n", str5.c_str());
						fprintf(ptrFile, "%s\n", str6.c_str());
						fprintf(ptrFile, "%s\n", str7.c_str());
						fprintf(ptrFile, "%s\n", str8.c_str());
						fprintf(ptrFile, "%s\n", str9.c_str());
						fprintf(ptrFile, "%s\n", str10.c_str());
						fprintf(ptrFile, "%s\n", str11.c_str());
						fprintf(ptrFile, "%s\n", str12.c_str());
						fprintf(ptrFile, "%s\n", str13.c_str());
						fprintf(ptrFile, "%s\n", str14.c_str());
						fprintf(ptrFile, "%s\n", str15.c_str());
						fprintf(ptrFile, "%s\n", str16.c_str());
						fprintf(ptrFile, "%s\n", str17.c_str());
						fprintf(ptrFile, "%s\n", str18.c_str());
						fprintf(ptrFile, "%s\n", str19.c_str());
						fprintf(ptrFile, "%s\n", str20.c_str());
						fprintf(ptrFile, "%s\n", str21.c_str());
						fprintf(ptrFile, "%s\n", str22.c_str());
						fprintf(ptrFile, "%s\n", str23.c_str());
						fprintf(ptrFile, "%s\n", str24.c_str());
						fprintf(ptrFile, "%s\n", str25.c_str());
						fprintf(ptrFile, "%s\n", str26.c_str());
						fprintf(ptrFile, "%s\n", str27.c_str());
						fprintf(ptrFile, "%s\n", str28.c_str());
						fprintf(ptrFile, "%s\n", str29.c_str());
						fprintf(ptrFile, "%s\n", str30.c_str());
						fprintf(ptrFile, "%s\n", str31.c_str());
						fprintf(ptrFile, "%s\n", str32.c_str());
						fprintf(ptrFile, "%s\n", str33.c_str());
						fprintf(ptrFile, "%s\n", str34.c_str());
						fprintf(ptrFile, "%s\n", str35.c_str());
						fprintf(ptrFile, "%s\n", str36.c_str());
						fprintf(ptrFile, "%s\n", str37.c_str());
						fprintf(ptrFile, "%s\n", str38.c_str());
						fprintf(ptrFile, "%s\n", str39.c_str());
						fprintf(ptrFile, "%s\n", str40.c_str());
						fprintf(ptrFile, "%s\n", str41.c_str());
						fprintf(ptrFile, "%s\n", str42.c_str());
						fprintf(ptrFile, "%s\n", str43.c_str());
						fprintf(ptrFile, "%s\n", str44.c_str());
						fprintf(ptrFile, "%s\n", str45.c_str());
						fprintf(ptrFile, "%s\n", str46.c_str());
						fprintf(ptrFile, "%s\n", str47.c_str());
						fprintf(ptrFile, "%s\n", str48.c_str());
						fprintf(ptrFile, "%s\n", str49.c_str());
						fprintf(ptrFile, "%s\n", str50.c_str());
						fprintf(ptrFile, "%s\n", str51.c_str());
						fprintf(ptrFile, "%s\n", str52.c_str());
						fprintf(ptrFile, "%s\n", str53.c_str());
						fprintf(ptrFile, "%s\n", str54.c_str());
						fprintf(ptrFile, "%s\n", str55.c_str());
						fprintf(ptrFile, "%s\n", str56.c_str());
						fprintf(ptrFile, "%s\n", str57.c_str());
						fprintf(ptrFile, "%s\n", str58.c_str());
						fprintf(ptrFile, "%s\n", str59.c_str());
						fprintf(ptrFile, "%s\n", str60.c_str());
						fprintf(ptrFile, "%s\n", str61.c_str());
						fprintf(ptrFile, "%s\n", str62.c_str());
						fprintf(ptrFile, "%s\n", str63.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
					else {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s%s\n", str0.c_str(), kstr0.c_str());
						fprintf(ptrFile, "%s%s\n", str1.c_str(), kstr1.c_str());
						fprintf(ptrFile, "%s%s\n", str2.c_str(), kstr2.c_str());
						fprintf(ptrFile, "%s%s\n", str3.c_str(), kstr3.c_str());
						fprintf(ptrFile, "%s%s\n", str4.c_str(), kstr4.c_str());
						fprintf(ptrFile, "%s%s\n", str5.c_str(), kstr5.c_str());
						fprintf(ptrFile, "%s%s\n", str6.c_str(), kstr6.c_str());
						fprintf(ptrFile, "%s%s\n", str7.c_str(), kstr7.c_str());
						fprintf(ptrFile, "%s%s\n", str8.c_str(), kstr8.c_str());
						fprintf(ptrFile, "%s%s\n", str9.c_str(), kstr9.c_str());
						fprintf(ptrFile, "%s%s\n", str10.c_str(), kstr10.c_str());
						fprintf(ptrFile, "%s%s\n", str11.c_str(), kstr11.c_str());
						fprintf(ptrFile, "%s%s\n", str12.c_str(), kstr12.c_str());
						fprintf(ptrFile, "%s%s\n", str13.c_str(), kstr13.c_str());
						fprintf(ptrFile, "%s%s\n", str14.c_str(), kstr14.c_str());
						fprintf(ptrFile, "%s%s\n", str15.c_str(), kstr15.c_str());
						fprintf(ptrFile, "%s%s\n", str16.c_str(), kstr16.c_str());
						fprintf(ptrFile, "%s%s\n", str17.c_str(), kstr17.c_str());
						fprintf(ptrFile, "%s%s\n", str18.c_str(), kstr18.c_str());
						fprintf(ptrFile, "%s%s\n", str19.c_str(), kstr19.c_str());
						fprintf(ptrFile, "%s%s\n", str20.c_str(), kstr20.c_str());
						fprintf(ptrFile, "%s%s\n", str21.c_str(), kstr21.c_str());
						fprintf(ptrFile, "%s%s\n", str22.c_str(), kstr22.c_str());
						fprintf(ptrFile, "%s%s\n", str23.c_str(), kstr23.c_str());
						fprintf(ptrFile, "%s%s\n", str24.c_str(), kstr24.c_str());
						fprintf(ptrFile, "%s%s\n", str25.c_str(), kstr25.c_str());
						fprintf(ptrFile, "%s%s\n", str26.c_str(), kstr26.c_str());
						fprintf(ptrFile, "%s%s\n", str27.c_str(), kstr27.c_str());
						fprintf(ptrFile, "%s%s\n", str28.c_str(), kstr28.c_str());
						fprintf(ptrFile, "%s%s\n", str29.c_str(), kstr29.c_str());
						fprintf(ptrFile, "%s%s\n", str30.c_str(), kstr30.c_str());
						fprintf(ptrFile, "%s%s\n", str31.c_str(), kstr31.c_str());
						fprintf(ptrFile, "%s%s\n", str32.c_str(), kstr32.c_str());
						fprintf(ptrFile, "%s%s\n", str33.c_str(), kstr33.c_str());
						fprintf(ptrFile, "%s%s\n", str34.c_str(), kstr34.c_str());
						fprintf(ptrFile, "%s%s\n", str35.c_str(), kstr35.c_str());
						fprintf(ptrFile, "%s%s\n", str36.c_str(), kstr36.c_str());
						fprintf(ptrFile, "%s%s\n", str37.c_str(), kstr37.c_str());
						fprintf(ptrFile, "%s%s\n", str38.c_str(), kstr38.c_str());
						fprintf(ptrFile, "%s%s\n", str39.c_str(), kstr39.c_str());
						fprintf(ptrFile, "%s%s\n", str40.c_str(), kstr40.c_str());
						fprintf(ptrFile, "%s%s\n", str41.c_str(), kstr41.c_str());
						fprintf(ptrFile, "%s%s\n", str42.c_str(), kstr42.c_str());
						fprintf(ptrFile, "%s%s\n", str43.c_str(), kstr43.c_str());
						fprintf(ptrFile, "%s%s\n", str44.c_str(), kstr44.c_str());
						fprintf(ptrFile, "%s%s\n", str45.c_str(), kstr45.c_str());
						fprintf(ptrFile, "%s%s\n", str46.c_str(), kstr46.c_str());
						fprintf(ptrFile, "%s%s\n", str47.c_str(), kstr47.c_str());
						fprintf(ptrFile, "%s%s\n", str48.c_str(), kstr48.c_str());
						fprintf(ptrFile, "%s%s\n", str49.c_str(), kstr49.c_str());
						fprintf(ptrFile, "%s%s\n", str50.c_str(), kstr50.c_str());
						fprintf(ptrFile, "%s%s\n", str51.c_str(), kstr51.c_str());
						fprintf(ptrFile, "%s%s\n", str52.c_str(), kstr52.c_str());
						fprintf(ptrFile, "%s%s\n", str53.c_str(), kstr53.c_str());
						fprintf(ptrFile, "%s%s\n", str54.c_str(), kstr54.c_str());
						fprintf(ptrFile, "%s%s\n", str55.c_str(), kstr55.c_str());
						fprintf(ptrFile, "%s%s\n", str56.c_str(), kstr56.c_str());
						fprintf(ptrFile, "%s%s\n", str57.c_str(), kstr57.c_str());
						fprintf(ptrFile, "%s%s\n", str58.c_str(), kstr58.c_str());
						fprintf(ptrFile, "%s%s\n", str59.c_str(), kstr59.c_str());
						fprintf(ptrFile, "%s%s\n", str60.c_str(), kstr60.c_str());
						fprintf(ptrFile, "%s%s\n", str61.c_str(), kstr61.c_str());
						fprintf(ptrFile, "%s%s\n", str62.c_str(), kstr62.c_str());
						fprintf(ptrFile, "%s%s\n", str63.c_str(), kstr63.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;

					}
				}
			}
		}
		if (rekey == 4 || rekey == 5 || rekey == 6) {

			if (vremyax > nbit) {
				vremyax = 1;
			}
			if (minuty == 300) {

				char* ctimeBuff;
				time_t now = time(NULL);
				ctimeBuff = ctime(&now);

				if (nbit2 > 13) {

					FILE* ptrFile = fopen("NEXT-Passphrases.txt", "w+");
					fprintf(ptrFile, "%s\n", str0.c_str());
					fprintf(ptrFile, "%s\n", str1.c_str());
					fprintf(ptrFile, "%s\n", str2.c_str());
					fprintf(ptrFile, "%s\n", str3.c_str());
					fprintf(ptrFile, "%s\n", str4.c_str());
					fprintf(ptrFile, "%s\n", str5.c_str());
					fprintf(ptrFile, "%s\n", str6.c_str());
					fprintf(ptrFile, "%s\n", str7.c_str());
					fprintf(ptrFile, "%s\n", str8.c_str());
					fprintf(ptrFile, "%s\n", str9.c_str());
					fprintf(ptrFile, "%s\n", str10.c_str());
					fprintf(ptrFile, "%s\n", str11.c_str());
					fprintf(ptrFile, "%s\n", str12.c_str());
					fprintf(ptrFile, "%s\n", str13.c_str());
					fprintf(ptrFile, "%s\n", str14.c_str());
					fprintf(ptrFile, "%s\n", str15.c_str());
					fprintf(ptrFile, "%s\n", str16.c_str());
					fprintf(ptrFile, "%s\n", str17.c_str());
					fprintf(ptrFile, "%s\n", str18.c_str());
					fprintf(ptrFile, "%s\n", str19.c_str());
					fprintf(ptrFile, "%s\n", str20.c_str());
					fprintf(ptrFile, "%s\n", str21.c_str());
					fprintf(ptrFile, "%s\n", str22.c_str());
					fprintf(ptrFile, "%s\n", str23.c_str());
					fprintf(ptrFile, "%s\n", str24.c_str());
					fprintf(ptrFile, "%s\n", str25.c_str());
					fprintf(ptrFile, "%s\n", str26.c_str());
					fprintf(ptrFile, "%s\n", str27.c_str());
					fprintf(ptrFile, "%s\n", str28.c_str());
					fprintf(ptrFile, "%s\n", str29.c_str());
					fprintf(ptrFile, "%s\n", str30.c_str());
					fprintf(ptrFile, "%s\n", str31.c_str());
					fprintf(ptrFile, "%s\n", str32.c_str());
					fprintf(ptrFile, "%s\n", str33.c_str());
					fprintf(ptrFile, "%s\n", str34.c_str());
					fprintf(ptrFile, "%s\n", str35.c_str());
					fprintf(ptrFile, "%s\n", str36.c_str());
					fprintf(ptrFile, "%s\n", str37.c_str());
					fprintf(ptrFile, "%s\n", str38.c_str());
					fprintf(ptrFile, "%s\n", str39.c_str());
					fprintf(ptrFile, "%s\n", str40.c_str());
					fprintf(ptrFile, "%s\n", str41.c_str());
					fprintf(ptrFile, "%s\n", str42.c_str());
					fprintf(ptrFile, "%s\n", str43.c_str());
					fprintf(ptrFile, "%s\n", str44.c_str());
					fprintf(ptrFile, "%s\n", str45.c_str());
					fprintf(ptrFile, "%s\n", str46.c_str());
					fprintf(ptrFile, "%s\n", str47.c_str());
					fprintf(ptrFile, "%s\n", str48.c_str());
					fprintf(ptrFile, "%s\n", str49.c_str());
					fprintf(ptrFile, "%s\n", str50.c_str());
					fprintf(ptrFile, "%s\n", str51.c_str());
					fprintf(ptrFile, "%s\n", str52.c_str());
					fprintf(ptrFile, "%s\n", str53.c_str());
					fprintf(ptrFile, "%s\n", str54.c_str());
					fprintf(ptrFile, "%s\n", str55.c_str());
					fprintf(ptrFile, "%s\n", str56.c_str());
					fprintf(ptrFile, "%s\n", str57.c_str());
					fprintf(ptrFile, "%s\n", str58.c_str());
					fprintf(ptrFile, "%s\n", str59.c_str());
					fprintf(ptrFile, "%s\n", str60.c_str());
					fprintf(ptrFile, "%s\n", str61.c_str());
					fprintf(ptrFile, "%s\n", str62.c_str());
					fprintf(ptrFile, "%s\n", str63.c_str());
					fprintf(ptrFile, "created: %s\n", ctimeBuff);
					fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with passphrases)\n");
					fprintf(ptrFile, "To continue, rename this file to Passphrases.txt");
					fclose(ptrFile);
					minuty = 1;

				}
				else {

					FILE* ptrFile = fopen("NEXT-Passphrases.txt", "w+");
					fprintf(ptrFile, "%s\n", str0.c_str());
					fprintf(ptrFile, "%s\n", str1.c_str());
					fprintf(ptrFile, "%s\n", str2.c_str());
					fprintf(ptrFile, "%s\n", str3.c_str());
					fprintf(ptrFile, "%s\n", str4.c_str());
					fprintf(ptrFile, "%s\n", str5.c_str());
					fprintf(ptrFile, "%s\n", str6.c_str());
					fprintf(ptrFile, "%s\n", str7.c_str());
					fprintf(ptrFile, "%s\n", str8.c_str());
					fprintf(ptrFile, "%s\n", str9.c_str());
					fprintf(ptrFile, "%s\n", str10.c_str());
					fprintf(ptrFile, "%s\n", str11.c_str());
					fprintf(ptrFile, "created: %s\n", ctimeBuff);
					fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with passphrases)\n");
					fprintf(ptrFile, "To continue, rename this file to Passphrases.txt");
					fclose(ptrFile);
					minuty = 1;
				}

			}
		}
		if (rekey == 7) {

			if (minuty == 300) {

				char* ctimeBuff;
				time_t now = time(NULL);
				ctimeBuff = ctime(&now);

				if (nbit2 < 13) {

					if (nbit == 0) {

						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s\n", str0.c_str());
						fprintf(ptrFile, "%s\n", str1.c_str());
						fprintf(ptrFile, "%s\n", str2.c_str());
						fprintf(ptrFile, "%s\n", str3.c_str());
						fprintf(ptrFile, "%s\n", str4.c_str());
						fprintf(ptrFile, "%s\n", str5.c_str());
						fprintf(ptrFile, "%s\n", str6.c_str());
						fprintf(ptrFile, "%s\n", str7.c_str());
						fprintf(ptrFile, "%s\n", str8.c_str());
						fprintf(ptrFile, "%s\n", str9.c_str());
						fprintf(ptrFile, "%s\n", str10.c_str());
						fprintf(ptrFile, "%s\n", str11.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
					else {

						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s%s\n", str0.c_str(), kstr0.c_str());
						fprintf(ptrFile, "%s%s\n", str1.c_str(), kstr1.c_str());
						fprintf(ptrFile, "%s%s\n", str2.c_str(), kstr2.c_str());
						fprintf(ptrFile, "%s%s\n", str3.c_str(), kstr3.c_str());
						fprintf(ptrFile, "%s%s\n", str4.c_str(), kstr4.c_str());
						fprintf(ptrFile, "%s%s\n", str5.c_str(), kstr5.c_str());
						fprintf(ptrFile, "%s%s\n", str6.c_str(), kstr6.c_str());
						fprintf(ptrFile, "%s%s\n", str7.c_str(), kstr7.c_str());
						fprintf(ptrFile, "%s%s\n", str8.c_str(), kstr8.c_str());
						fprintf(ptrFile, "%s%s\n", str9.c_str(), kstr9.c_str());
						fprintf(ptrFile, "%s%s\n", str10.c_str(), kstr10.c_str());
						fprintf(ptrFile, "%s%s\n", str11.c_str(), kstr11.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
				}
				else {
					if (nbit == 0) {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s\n", str0.c_str());
						fprintf(ptrFile, "%s\n", str1.c_str());
						fprintf(ptrFile, "%s\n", str2.c_str());
						fprintf(ptrFile, "%s\n", str3.c_str());
						fprintf(ptrFile, "%s\n", str4.c_str());
						fprintf(ptrFile, "%s\n", str5.c_str());
						fprintf(ptrFile, "%s\n", str6.c_str());
						fprintf(ptrFile, "%s\n", str7.c_str());
						fprintf(ptrFile, "%s\n", str8.c_str());
						fprintf(ptrFile, "%s\n", str9.c_str());
						fprintf(ptrFile, "%s\n", str10.c_str());
						fprintf(ptrFile, "%s\n", str11.c_str());
						fprintf(ptrFile, "%s\n", str12.c_str());
						fprintf(ptrFile, "%s\n", str13.c_str());
						fprintf(ptrFile, "%s\n", str14.c_str());
						fprintf(ptrFile, "%s\n", str15.c_str());
						fprintf(ptrFile, "%s\n", str16.c_str());
						fprintf(ptrFile, "%s\n", str17.c_str());
						fprintf(ptrFile, "%s\n", str18.c_str());
						fprintf(ptrFile, "%s\n", str19.c_str());
						fprintf(ptrFile, "%s\n", str20.c_str());
						fprintf(ptrFile, "%s\n", str21.c_str());
						fprintf(ptrFile, "%s\n", str22.c_str());
						fprintf(ptrFile, "%s\n", str23.c_str());
						fprintf(ptrFile, "%s\n", str24.c_str());
						fprintf(ptrFile, "%s\n", str25.c_str());
						fprintf(ptrFile, "%s\n", str26.c_str());
						fprintf(ptrFile, "%s\n", str27.c_str());
						fprintf(ptrFile, "%s\n", str28.c_str());
						fprintf(ptrFile, "%s\n", str29.c_str());
						fprintf(ptrFile, "%s\n", str30.c_str());
						fprintf(ptrFile, "%s\n", str31.c_str());
						fprintf(ptrFile, "%s\n", str32.c_str());
						fprintf(ptrFile, "%s\n", str33.c_str());
						fprintf(ptrFile, "%s\n", str34.c_str());
						fprintf(ptrFile, "%s\n", str35.c_str());
						fprintf(ptrFile, "%s\n", str36.c_str());
						fprintf(ptrFile, "%s\n", str37.c_str());
						fprintf(ptrFile, "%s\n", str38.c_str());
						fprintf(ptrFile, "%s\n", str39.c_str());
						fprintf(ptrFile, "%s\n", str40.c_str());
						fprintf(ptrFile, "%s\n", str41.c_str());
						fprintf(ptrFile, "%s\n", str42.c_str());
						fprintf(ptrFile, "%s\n", str43.c_str());
						fprintf(ptrFile, "%s\n", str44.c_str());
						fprintf(ptrFile, "%s\n", str45.c_str());
						fprintf(ptrFile, "%s\n", str46.c_str());
						fprintf(ptrFile, "%s\n", str47.c_str());
						fprintf(ptrFile, "%s\n", str48.c_str());
						fprintf(ptrFile, "%s\n", str49.c_str());
						fprintf(ptrFile, "%s\n", str50.c_str());
						fprintf(ptrFile, "%s\n", str51.c_str());
						fprintf(ptrFile, "%s\n", str52.c_str());
						fprintf(ptrFile, "%s\n", str53.c_str());
						fprintf(ptrFile, "%s\n", str54.c_str());
						fprintf(ptrFile, "%s\n", str55.c_str());
						fprintf(ptrFile, "%s\n", str56.c_str());
						fprintf(ptrFile, "%s\n", str57.c_str());
						fprintf(ptrFile, "%s\n", str58.c_str());
						fprintf(ptrFile, "%s\n", str59.c_str());
						fprintf(ptrFile, "%s\n", str60.c_str());
						fprintf(ptrFile, "%s\n", str61.c_str());
						fprintf(ptrFile, "%s\n", str62.c_str());
						fprintf(ptrFile, "%s\n", str63.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;
					}
					else {
						FILE* ptrFile = fopen("NEXT-WIF.txt", "w+");
						fprintf(ptrFile, "%s%s\n", str0.c_str(), kstr0.c_str());
						fprintf(ptrFile, "%s%s\n", str1.c_str(), kstr1.c_str());
						fprintf(ptrFile, "%s%s\n", str2.c_str(), kstr2.c_str());
						fprintf(ptrFile, "%s%s\n", str3.c_str(), kstr3.c_str());
						fprintf(ptrFile, "%s%s\n", str4.c_str(), kstr4.c_str());
						fprintf(ptrFile, "%s%s\n", str5.c_str(), kstr5.c_str());
						fprintf(ptrFile, "%s%s\n", str6.c_str(), kstr6.c_str());
						fprintf(ptrFile, "%s%s\n", str7.c_str(), kstr7.c_str());
						fprintf(ptrFile, "%s%s\n", str8.c_str(), kstr8.c_str());
						fprintf(ptrFile, "%s%s\n", str9.c_str(), kstr9.c_str());
						fprintf(ptrFile, "%s%s\n", str10.c_str(), kstr10.c_str());
						fprintf(ptrFile, "%s%s\n", str11.c_str(), kstr11.c_str());
						fprintf(ptrFile, "%s%s\n", str12.c_str(), kstr12.c_str());
						fprintf(ptrFile, "%s%s\n", str13.c_str(), kstr13.c_str());
						fprintf(ptrFile, "%s%s\n", str14.c_str(), kstr14.c_str());
						fprintf(ptrFile, "%s%s\n", str15.c_str(), kstr15.c_str());
						fprintf(ptrFile, "%s%s\n", str16.c_str(), kstr16.c_str());
						fprintf(ptrFile, "%s%s\n", str17.c_str(), kstr17.c_str());
						fprintf(ptrFile, "%s%s\n", str18.c_str(), kstr18.c_str());
						fprintf(ptrFile, "%s%s\n", str19.c_str(), kstr19.c_str());
						fprintf(ptrFile, "%s%s\n", str20.c_str(), kstr20.c_str());
						fprintf(ptrFile, "%s%s\n", str21.c_str(), kstr21.c_str());
						fprintf(ptrFile, "%s%s\n", str22.c_str(), kstr22.c_str());
						fprintf(ptrFile, "%s%s\n", str23.c_str(), kstr23.c_str());
						fprintf(ptrFile, "%s%s\n", str24.c_str(), kstr24.c_str());
						fprintf(ptrFile, "%s%s\n", str25.c_str(), kstr25.c_str());
						fprintf(ptrFile, "%s%s\n", str26.c_str(), kstr26.c_str());
						fprintf(ptrFile, "%s%s\n", str27.c_str(), kstr27.c_str());
						fprintf(ptrFile, "%s%s\n", str28.c_str(), kstr28.c_str());
						fprintf(ptrFile, "%s%s\n", str29.c_str(), kstr29.c_str());
						fprintf(ptrFile, "%s%s\n", str30.c_str(), kstr30.c_str());
						fprintf(ptrFile, "%s%s\n", str31.c_str(), kstr31.c_str());
						fprintf(ptrFile, "%s%s\n", str32.c_str(), kstr32.c_str());
						fprintf(ptrFile, "%s%s\n", str33.c_str(), kstr33.c_str());
						fprintf(ptrFile, "%s%s\n", str34.c_str(), kstr34.c_str());
						fprintf(ptrFile, "%s%s\n", str35.c_str(), kstr35.c_str());
						fprintf(ptrFile, "%s%s\n", str36.c_str(), kstr36.c_str());
						fprintf(ptrFile, "%s%s\n", str37.c_str(), kstr37.c_str());
						fprintf(ptrFile, "%s%s\n", str38.c_str(), kstr38.c_str());
						fprintf(ptrFile, "%s%s\n", str39.c_str(), kstr39.c_str());
						fprintf(ptrFile, "%s%s\n", str40.c_str(), kstr40.c_str());
						fprintf(ptrFile, "%s%s\n", str41.c_str(), kstr41.c_str());
						fprintf(ptrFile, "%s%s\n", str42.c_str(), kstr42.c_str());
						fprintf(ptrFile, "%s%s\n", str43.c_str(), kstr43.c_str());
						fprintf(ptrFile, "%s%s\n", str44.c_str(), kstr44.c_str());
						fprintf(ptrFile, "%s%s\n", str45.c_str(), kstr45.c_str());
						fprintf(ptrFile, "%s%s\n", str46.c_str(), kstr46.c_str());
						fprintf(ptrFile, "%s%s\n", str47.c_str(), kstr47.c_str());
						fprintf(ptrFile, "%s%s\n", str48.c_str(), kstr48.c_str());
						fprintf(ptrFile, "%s%s\n", str49.c_str(), kstr49.c_str());
						fprintf(ptrFile, "%s%s\n", str50.c_str(), kstr50.c_str());
						fprintf(ptrFile, "%s%s\n", str51.c_str(), kstr51.c_str());
						fprintf(ptrFile, "%s%s\n", str52.c_str(), kstr52.c_str());
						fprintf(ptrFile, "%s%s\n", str53.c_str(), kstr53.c_str());
						fprintf(ptrFile, "%s%s\n", str54.c_str(), kstr54.c_str());
						fprintf(ptrFile, "%s%s\n", str55.c_str(), kstr55.c_str());
						fprintf(ptrFile, "%s%s\n", str56.c_str(), kstr56.c_str());
						fprintf(ptrFile, "%s%s\n", str57.c_str(), kstr57.c_str());
						fprintf(ptrFile, "%s%s\n", str58.c_str(), kstr58.c_str());
						fprintf(ptrFile, "%s%s\n", str59.c_str(), kstr59.c_str());
						fprintf(ptrFile, "%s%s\n", str60.c_str(), kstr60.c_str());
						fprintf(ptrFile, "%s%s\n", str61.c_str(), kstr61.c_str());
						fprintf(ptrFile, "%s%s\n", str62.c_str(), kstr62.c_str());
						fprintf(ptrFile, "%s%s\n", str63.c_str(), kstr63.c_str());
						fprintf(ptrFile, "created: %s\n", ctimeBuff);
						fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with WIF L..,K.., 52 letters, 5.. 51 letters)\n");
						fprintf(ptrFile, "To continue, rename this file to WIF.txt");
						fclose(ptrFile);
						minuty = 1;

					}
				}
			}
		}
		if (rekey == 8) {

			if (minuty == 300) {

				char* ctimeBuff;
				time_t now = time(NULL);
				ctimeBuff = ctime(&now);

				if (nbit2 < 13) {

					FILE* ptrFile = fopen("NEXT-Minikeys.txt", "w+");
					fprintf(ptrFile, "%s\n", str0.c_str());
					fprintf(ptrFile, "%s\n", str1.c_str());
					fprintf(ptrFile, "%s\n", str2.c_str());
					fprintf(ptrFile, "%s\n", str3.c_str());
					fprintf(ptrFile, "%s\n", str4.c_str());
					fprintf(ptrFile, "%s\n", str5.c_str());
					fprintf(ptrFile, "%s\n", str6.c_str());
					fprintf(ptrFile, "%s\n", str7.c_str());
					fprintf(ptrFile, "%s\n", str8.c_str());
					fprintf(ptrFile, "%s\n", str9.c_str());
					fprintf(ptrFile, "%s\n", str10.c_str());
					fprintf(ptrFile, "%s\n", str11.c_str());
					fprintf(ptrFile, "created: %s\n", ctimeBuff);
					fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with Minikeys S...)\n");
					fprintf(ptrFile, "To continue, rename NEXT-Minikeys.txt to Minikeys.txt");
					fclose(ptrFile);
					minuty = 1;
				}
				else {
					FILE* ptrFile = fopen("NEXT-Minikeys.txt", "w+");
					fprintf(ptrFile, "%s\n", str0.c_str());
					fprintf(ptrFile, "%s\n", str1.c_str());
					fprintf(ptrFile, "%s\n", str2.c_str());
					fprintf(ptrFile, "%s\n", str3.c_str());
					fprintf(ptrFile, "%s\n", str4.c_str());
					fprintf(ptrFile, "%s\n", str5.c_str());
					fprintf(ptrFile, "%s\n", str6.c_str());
					fprintf(ptrFile, "%s\n", str7.c_str());
					fprintf(ptrFile, "%s\n", str8.c_str());
					fprintf(ptrFile, "%s\n", str9.c_str());
					fprintf(ptrFile, "%s\n", str10.c_str());
					fprintf(ptrFile, "%s\n", str11.c_str());
					fprintf(ptrFile, "%s\n", str12.c_str());
					fprintf(ptrFile, "%s\n", str13.c_str());
					fprintf(ptrFile, "%s\n", str14.c_str());
					fprintf(ptrFile, "%s\n", str15.c_str());
					fprintf(ptrFile, "%s\n", str16.c_str());
					fprintf(ptrFile, "%s\n", str17.c_str());
					fprintf(ptrFile, "%s\n", str18.c_str());
					fprintf(ptrFile, "%s\n", str19.c_str());
					fprintf(ptrFile, "%s\n", str20.c_str());
					fprintf(ptrFile, "%s\n", str21.c_str());
					fprintf(ptrFile, "%s\n", str22.c_str());
					fprintf(ptrFile, "%s\n", str23.c_str());
					fprintf(ptrFile, "%s\n", str24.c_str());
					fprintf(ptrFile, "%s\n", str25.c_str());
					fprintf(ptrFile, "%s\n", str26.c_str());
					fprintf(ptrFile, "%s\n", str27.c_str());
					fprintf(ptrFile, "%s\n", str28.c_str());
					fprintf(ptrFile, "%s\n", str29.c_str());
					fprintf(ptrFile, "%s\n", str30.c_str());
					fprintf(ptrFile, "%s\n", str31.c_str());
					fprintf(ptrFile, "%s\n", str32.c_str());
					fprintf(ptrFile, "%s\n", str33.c_str());
					fprintf(ptrFile, "%s\n", str34.c_str());
					fprintf(ptrFile, "%s\n", str35.c_str());
					fprintf(ptrFile, "%s\n", str36.c_str());
					fprintf(ptrFile, "%s\n", str37.c_str());
					fprintf(ptrFile, "%s\n", str38.c_str());
					fprintf(ptrFile, "%s\n", str39.c_str());
					fprintf(ptrFile, "%s\n", str40.c_str());
					fprintf(ptrFile, "%s\n", str41.c_str());
					fprintf(ptrFile, "%s\n", str42.c_str());
					fprintf(ptrFile, "%s\n", str43.c_str());
					fprintf(ptrFile, "%s\n", str44.c_str());
					fprintf(ptrFile, "%s\n", str45.c_str());
					fprintf(ptrFile, "%s\n", str46.c_str());
					fprintf(ptrFile, "%s\n", str47.c_str());
					fprintf(ptrFile, "%s\n", str48.c_str());
					fprintf(ptrFile, "%s\n", str49.c_str());
					fprintf(ptrFile, "%s\n", str50.c_str());
					fprintf(ptrFile, "%s\n", str51.c_str());
					fprintf(ptrFile, "%s\n", str52.c_str());
					fprintf(ptrFile, "%s\n", str53.c_str());
					fprintf(ptrFile, "%s\n", str54.c_str());
					fprintf(ptrFile, "%s\n", str55.c_str());
					fprintf(ptrFile, "%s\n", str56.c_str());
					fprintf(ptrFile, "%s\n", str57.c_str());
					fprintf(ptrFile, "%s\n", str58.c_str());
					fprintf(ptrFile, "%s\n", str59.c_str());
					fprintf(ptrFile, "%s\n", str60.c_str());
					fprintf(ptrFile, "%s\n", str61.c_str());
					fprintf(ptrFile, "%s\n", str62.c_str());
					fprintf(ptrFile, "%s\n", str63.c_str());
					fprintf(ptrFile, "created: %s\n", ctimeBuff);
					fprintf(ptrFile, "One line = 1 core. Maximum -t 64 (64 lines with Minikeys S...)\n");
					fprintf(ptrFile, "To continue, rename NEXT-Minikeys.txt to Minikeys.txt");
					fclose(ptrFile);
					minuty = 1;
				}
			}
		}
		vremyax++;

		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// KeyRate smoothing
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);

		zhdat++;

		if (rekey == 1) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Skip: %s]   ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}
		if (rekey == 2) {

			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Skip: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}

		if (rekey == 3) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Skip: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}

		if (rekey == 4) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Replaces: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}
		if (rekey == 5) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Replaces: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}
		if (rekey == 6) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] [Replaces: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str(),
					formatThousands(counters2).c_str());
			}
		}
		if (rekey == 7) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str());
			}
		}
		if (rekey == 8) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str());
			}
		}

		if (rekey == 9) {
			double avgKeyRate2 = avgKeyRate * 1;
			double avgKeyRate3 = avgKeyRate2 / nbGPUThread;

			input2.Add(avgKeyRate3);
			//bool isComp;
			bool compressed = (searchMode == SEARCH_COMPRESSED);
			string pAddr = secp->GetPrivAddress(compressed, input2);


			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]  ",
					toTimeStr(t1, timeStr),
					pAddr.c_str(),
					input2.GetBase16().c_str(),
					nbFoundKey,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str());
			}
		}
		if (rekey == 10) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str());
			}
		}
		if (rekey == 11) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] [%s] [%s] [CPU: %.2f Kk/s] [F: %d] [T: %s] ",
					toTimeStr(t1, timeStr),
					input1.c_str(),
					input2.GetBase16().c_str(),
					avgKeyRate / 1000.0,
					nbFoundKey,
					formatThousands(count).c_str());
			}
		}
		
		
		if (rKey > 0) {
			if ((count - lastrKey) > (18000000000000000000 * rKey)) {
				// rKey request
				rKeyRequest(params);
				lastrKey = count;
				rKeyCount++;
				rKeyCount2 += rKeyCount;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		
	}

	free(params);

	}

// ----------------------------------------------------------------------------

std::string Fialka::GetHex(std::vector<unsigned char> &buffer)
{
	std::string ret;

	char tmp[128];
	for (int i = 0; i < (int)buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int Fialka::CheckBloomBinary(const uint8_t * _xx, uint32_t K_LENGTH)
{
	if (bloom->check(_xx, K_LENGTH) > 0) {
		uint8_t* temp_read;
		uint64_t half, min, max, current; //, current_offset
		int64_t rcmp;
		int32_t r = 0;
		min = 0;
		current = 0;
		max = TOTAL_COUNT;
		half = TOTAL_COUNT;
		while (!r && half >= 1) {
			half = (max - min) / 2;
			temp_read = DATA + ((current + half) * K_LENGTH);
			rcmp = memcmp(_xx, temp_read, K_LENGTH);
			if (rcmp == 0) {
				r = 1;  //Found!!
			}
			else {
				if (rcmp < 0) { //data < temp_read
					max = (max - half);
				}
				else { // data > temp_read
					min = (min + half);
				}
				current = min;
			}
		}
		return r;
	}
	return 0;
}

// ----------------------------------------------------------------------------

bool Fialka::MatchHash(uint32_t * _h)
{
	if (_h[0] == hash160Keccak[0] &&
		_h[1] == hash160Keccak[1] &&
		_h[2] == hash160Keccak[2] &&
		_h[3] == hash160Keccak[3] &&
		_h[4] == hash160Keccak[4]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

bool Fialka::MatchXPoint(uint32_t * _h)
{
	if (_h[0] == xpoint[0] &&
		_h[1] == xpoint[1] &&
		_h[2] == xpoint[2] &&
		_h[3] == xpoint[3] &&
		_h[4] == xpoint[4] &&
		_h[5] == xpoint[5] &&
		_h[6] == xpoint[6] &&
		_h[7] == xpoint[7]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

std::string Fialka::formatThousands(uint64_t x)
{
	char buf[32] = "";

	sprintf(buf, "%llu", x);

	std::string s(buf);

	int len = (int)s.length();

	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";

	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

	for (int i = 0; i < len; i++) {
		result += s[i];

		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}


// ----------------------------------------------------------------------------

char* Fialka::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}

// ----------------------------------------------------------------------------

//#include <gmp.h>
//#include <gmpxx.h>
// ((input - min) * 100) / (max - min)
//double Fialka::GetPercantage(uint64_t v)
//{
//	//Int val(v);
//	//mpz_class x(val.GetBase16().c_str(), 16);
//	//mpz_class r(rangeStart.GetBase16().c_str(), 16);
//	//x = x - mpz_class(rangeEnd.GetBase16().c_str(), 16);
//	//x = x * 100;
//	//mpf_class y(x);
//	//y = y / mpf_class(r);
//	return 0;// y.get_d();
//}

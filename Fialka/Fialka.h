#ifndef FialkaH
#define FialkaH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "Bloom.h"
#include "GPU/GPUEngine.h"
#ifdef WIN64
#include <Windows.h>
#endif

#define CPU_GRP_SIZE (1024*2)

class Fialka;

typedef struct {
	Fialka* obj;
	int  threadId;
	bool isRunning;
	bool hasStarted;

	int  gridSizeX;
	int  gridSizeY;
	int  gpuId;

	Int rangeStart;
	Int rangeEnd;
	bool rKeyRequest;
} TH_PARAM;


class Fialka
{

public:

	Fialka(const std::string& inputFile, int compMode, std::string& seed, std::string& zez, int searchMode, int coinType, bool useGpu,
		const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit, int nbit2, int zet, int display,
		const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit);

	Fialka(const std::vector<unsigned char>& hashORxpoint, int compMode, std::string seed, std::string zez, int searchMode, int coinType,
		bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit, int nbit2, int zet, int display,
		const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit);

	~Fialka();

	void Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit);
	void FindKeyCPU(TH_PARAM* p);
	void FindKeyGPU(TH_PARAM* p);

private:

	void InitGenratorTable();

	std::string GetHex(std::vector<unsigned char>& buffer);
	bool checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode);
	bool checkPrivKeyETH(std::string addr, Int& key, int32_t incr);
	bool checkPrivKeyX(Int& key, int32_t incr, bool mode);

	void checkMultiAddresses(bool compressed, Int key, int i, Point p1);
	void checkMultiAddressesETH(Int key, int i, Point p1);
	void checkSingleAddress(bool compressed, Int key, int i, Point p1);
	void checkSingleAddressETH(Int key, int i, Point p1);
	void checkMultiXPoints(bool compressed, Int key, int i, Point p1);
	void checkSingleXPoint(bool compressed, Int key, int i, Point p1);

	void checkMultiAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);
	void checkSingleAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);

	void output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey);
	bool isAlive(TH_PARAM* p);

	bool hasStarted(TH_PARAM* p);
	uint64_t getGPUCount();
	uint64_t getCPUCount();
	void rKeyRequest(TH_PARAM* p);
	void SetupRanges(uint32_t totalThreads);

	void getCPUStartingKey(Int& tRangeStart, Int& tRangeEnd, Int& key, Point& startP);
	void getGPUStartingKeys(Int& tRangeStart, Int& tRangeEnd, int groupSize, int nbThread, Int* keys, Point* p);

	int CheckBloomBinary(const uint8_t* _xx, uint32_t K_LENGTH);
	bool MatchHash(uint32_t* _h);
	bool MatchXPoint(uint32_t* _h);
	std::string formatThousands(uint64_t x);
	char* toTimeStr(int sec, char* timeStr);

	Secp256K1* secp;
	Bloom* bloom;
	uint64_t akk;
	uint64_t counters2;
	uint64_t counters[256];
	double startTime;
	int c1 = 0;
	int c2 = 0;
	int c3 = 0;
	int c4 = 0;
	int compMode;
	int searchMode;
	int coinType;
	uint64_t rekey;
	bool useGpu;
	bool endOfSearch;
	int nbCPUThread;
	int nbGPUThread;
	int nbFoundKey;
	uint64_t targetCounter;
	int nbit;
	int diz;
	int err;
	int stope;
	int kusok;
	std::string stroka;
	std::string outputFile;
	std::string inputFile;
	uint32_t hash160Keccak[5];
	uint32_t xpoint[8];
	bool useSSE;
	Int rangeStart8;
	Int rangeStart;
	Int rangeEnd;
	Int rangeDiff;
	Int rangeDiff2;
	Int rangeDiffcp;
	Int rangeDiffbar;
	Int gir;
	int trk = 0;
	Int razn;
	Int rhex;
	int minuty;
	int zhdat;
	uint64_t value777;
	uint32_t maxFound;
	uint64_t rKey;
	int zet;
	int display;
	int nbit2;
	int gpucores;
	uint64_t lastrKey;
	uint64_t rKeyCount2;
	int corres;
	uint8_t* DATA;
	uint64_t TOTAL_COUNT;
	uint64_t BLOOM_N;
	std::string input1;
	Int input2;
	std::string zamena;
	std::string seed;
	std::string zez;
	std::string str0;
	std::string str1;
	std::string str2;
	std::string str3;
	std::string str4;
	std::string str5;
	std::string str6;
	std::string str7;
	std::string str8;
	std::string str9;
	std::string str10;
	std::string str11;
	std::string str12;
	std::string str13;
	std::string str14;
	std::string str15;
	std::string str16;
	std::string str17;
	std::string str18;
	std::string str19;
	std::string str20;
	std::string str21;
	std::string str22;
	std::string str23;
	std::string str24;
	std::string str25;
	std::string str26;
	std::string str27;
	std::string str28;
	std::string str29;
	std::string str30;
	std::string str31;
	std::string str32;
	std::string str33;
	std::string str34;
	std::string str35;
	std::string str36;
	std::string str37;
	std::string str38;
	std::string str39;
	std::string str40;
	std::string str41;
	std::string str42;
	std::string str43;
	std::string str44;
	std::string str45;
	std::string str46;
	std::string str47;
	std::string str48;
	std::string str49;
	std::string str50;
	std::string str51;
	std::string str52;
	std::string str53;
	std::string str54;
	std::string str55;
	std::string str56;
	std::string str57;
	std::string str58;
	std::string str59;
	std::string str60;
	std::string str61;
	std::string str62;
	std::string str63;
	std::string str64;
	std::string kstr0;
	std::string kstr1;
	std::string kstr2;
	std::string kstr3;
	std::string kstr4;
	std::string kstr5;
	std::string kstr6;
	std::string kstr7;
	std::string kstr8;
	std::string kstr9;
	std::string kstr10;
	std::string kstr11;
	std::string kstr12;
	std::string kstr13;
	std::string kstr14;
	std::string kstr15;
	std::string kstr16;
	std::string kstr17;
	std::string kstr18;
	std::string kstr19;
	std::string kstr20;
	std::string kstr21;
	std::string kstr22;
	std::string kstr23;
	std::string kstr24;
	std::string kstr25;
	std::string kstr26;
	std::string kstr27;
	std::string kstr28;
	std::string kstr29;
	std::string kstr30;
	std::string kstr31;
	std::string kstr32;
	std::string kstr33;
	std::string kstr34;
	std::string kstr35;
	std::string kstr36;
	std::string kstr37;
	std::string kstr38;
	std::string kstr39;
	std::string kstr40;
	std::string kstr41;
	std::string kstr42;
	std::string kstr43;
	std::string kstr44;
	std::string kstr45;
	std::string kstr46;
	std::string kstr47;
	std::string kstr48;
	std::string kstr49;
	std::string kstr50;
	std::string kstr51;
	std::string kstr52;
	std::string kstr53;
	std::string kstr54;
	std::string kstr55;
	std::string kstr56;
	std::string kstr57;
	std::string kstr58;
	std::string kstr59;
	std::string kstr60;
	std::string kstr61;
	std::string kstr62;
	std::string kstr63;
	std::string kstr64;
	Int kisa;
	int vremyax;
	Int kisa0;
	Int kisa1;
	Int kisa2;
	Int kisa3;
	Int kisa4;
	Int kisa5;
	Int kisa6;
	Int kisa7;
	Int kisa8;
	Int kisa9;
	Int kisa10;
	Int kisa11;
	Int kisa12;
	Int kisa13;
	Int kisa14;
	Int kisa15;
	Int kisa16;
	Int kisa17;
	Int kisa18;
	Int kisa19;
	Int kisa20;
	Int kisa21;
	Int kisa22;
	Int kisa23;
	Int kisa24;
	Int kisa25;
	Int kisa26;
	Int kisa27;
	Int kisa28;
	Int kisa29;
	Int kisa30;
	Int kisa31;
	Int kisa32;
	Int kisa33;
	Int kisa34;
	Int kisa35;
	Int kisa36;
	Int kisa37;
	Int kisa38;
	Int kisa39;
	Int kisa40;
	Int kisa41;
	Int kisa42;
	Int kisa43;
	Int kisa44;
	Int kisa45;
	Int kisa46;
	Int kisa47;
	Int kisa48;
	Int kisa49;
	Int kisa50;
	Int kisa51;
	Int kisa52;
	Int kisa53;
	Int kisa54;
	Int kisa55;
	Int kisa56;
	Int kisa57;
	Int kisa58;
	Int kisa59;
	Int kisa60;
	Int kisa61;
	Int kisa62;
	Int kisa63;
	Int kisa64;
	Int key0;
	Int key1;
	Int key2;
	Int key3;
	Int key4;
	Int key5;
	Int key6;
	Int key7;
	Int key8;
	Int key9;
	Int key10;
	Int key11;
	Int key12;
	Int key13;
	Int key14;
	Int key15;
	Int key16;
	Int key17;
	Int key18;
	Int key19;
	Int key20;
	Int key21;
	Int key22;
	Int key23;
	Int key24;
	Int key25;
	Int key26;
	Int key27;
	Int key28;
	Int key29;
	Int key30;
	Int key31;
	Int key32;
	Int key33;
	Int key34;
	Int key35;
	Int key36;
	Int key37;
	Int key38;
	Int key39;
	Int key40;
	Int key41;
	Int key42;
	Int key43;
	Int key44;
	Int key45;
	Int key46;
	Int key47;
	Int key48;
	Int key49;
	Int key50;
	Int key51;
	Int key52;
	Int key53;
	Int key54;
	Int key55;
	Int key56;
	Int key57;
	Int key58;
	Int key59;
	Int key60;
	Int key61;
	Int key62;
	Int key63;
	Int key64;

#ifdef WIN64
	HANDLE ghMutex;
#else
	pthread_mutex_t  ghMutex;
#endif

};

#endif // FialkaH

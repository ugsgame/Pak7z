/*
 *  Pak7z - Pack files by LZMA(7z) compression.
 *
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>

extern "C"
{
#include "lzma\LzmaLib.h"
#include "lzma\LzmaEnc.h"
#include "lzma\Alloc.h"
}

#pragma warning(disable:4049)

//-----------------------------------------------------------------------------
// Definitions
//-----------------------------------------------------------------------------
typedef unsigned char TUint8;
typedef unsigned short TUint16;
typedef unsigned int TUint32;
typedef unsigned int TUint;

#define DICT_SIZE		1024*1024
#define ODATA_MAX		1024*1024*16	//16MB

#define ARGC_MAX		1024*10
#define ARG_LEN_MAX		256

TUint32 cryptTable[0x500];
#define FILE_NAME_LEN	80


/*
//-----------------------------------------------------------------------------

Usage:
pak7z.exe output.pak [list.txt]

list.txt:
@9	//compression level 9
file1
file2
...

@5	//compression level 5
file101
file102
...

@0	//store, no compression
file201
file202
...

//-----------------------------------------------------------------------------
*/
typedef struct _TPk3Header
{
	/*
	TUint16 fileNumber;	// how many files packed in the .pak
	TUint16 fileNameLen;	// eg. 256
	int fileNamePos;	// fileNamePos | 0x80000000(fileName compressed or not), deprecated in pak7z
	int fnSize;	// zFNSize or oFNSize, oFNSize = fileNameLen*fileNumber
	*/
	TUint32 fileNumber:12;	// how many files packed in the .pak
	TUint32 pakVersion:4;
	TUint32 zHeaderSize:16;
	TUint32 oDataSize;
	TUint32 zDataSize;
} TPk3Header;

typedef struct _TPakIndex
{
	TUint32 nHash1;
	TUint32 nHash2;
	TUint32 filePos;
	TUint32 oSize;
	TUint32 zSize;
	TUint32 flag;	// reserved
} TPakIndex;

typedef struct _TFileBlock
{
	TPakIndex index;
	char fileName[FILE_NAME_LEN];
	TUint8* oData;
//	TUint8* zData;
} TFileBlock;

//-----------------------------------------------------------------------------
// Hash string
//-----------------------------------------------------------------------------
void InitCryptTable()
{
	TUint32 seed = 0x00100001, index1 = 0, index2 = 0, i;
	
	for(index1 = 0; index1 < 0x100; index1++)
	{
		for(index2 = index1, i = 0; i < 5; i++, index2 += 0x100)
		{
			TUint32 temp1, temp2;
			
			seed = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;
			
			seed = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			cryptTable[index2] = (temp1 | temp2);
		}
	}
}

int CharUpper(char lc)
{
	if (lc>='a' && lc<='z') return lc+'A'-'a';
	return lc;
}

TUint32 HashStr(const char* str, TUint32 hashType)
{
	TUint32 seed1 = 0x7FED7FED, seed2 = 0xEEEEEEEE;
	while (*str)
	{
		int uc = CharUpper(*str++);
		int index = (hashType << 8) + uc;
		seed1 = cryptTable[index] ^ (seed1 + seed2);
		seed2 = uc + seed1 + seed2 + (seed2 << 5) + 3;
	}
	return seed1;
}

void PrintAligned(TFileBlock* files, int fileNumber)
{
	int* len = (int*)malloc(sizeof(int)*fileNumber);
	int i, max = 0;
	
	for (i=0; i<fileNumber; i++)
	{
		len[i] = strlen(files[i].fileName);
		max = len[i]>max ? len[i]:max;
	}

	int digits = 1;
	if (fileNumber>9999)
		printf("Not supported yet!!! %d files!\n",fileNumber);
	else if (fileNumber>999)
		digits = 4;
	else if (fileNumber>99)
		digits = 3;
	else if (fileNumber>9)
		digits = 2;

	for (i=0; i<fileNumber; i++)
	{
		int dot;
		double ratio = files[i].index.flag*100.0/files[i].index.oSize;

		switch (digits)
		{
		case 2:
			printf("[%02d]: `%s' ", i+1, files[i].fileName);
			break;
		case 3:
			printf("[%03d]: `%s' ", i+1, files[i].fileName);
			break;
		case 4:
			printf("[%04d]: `%s' ", i+1, files[i].fileName);
			break;
		default:
			printf("[%d]: `%s' ", i+1, files[i].fileName);
			break;
		}
		for (dot=0; dot<3+max-len[i]; dot++)
			printf(".");
	//	printf(" %6d -> %6d [%s%.1f%%]\n", files[i].index.oSize, files[i].index.zSize, ratio<10?" ":"", ratio);
		if (files[i].index.oSize < 1000)
			printf(" %7d -> %7d [%s%.1f%%]\n", files[i].index.oSize, files[i].index.flag, ratio<10?" ":"", ratio);
		else
		{
			printf(" %3d,%03d -> ", files[i].index.oSize/1000, files[i].index.oSize%1000);
			if (files[i].index.flag < 1000)
				printf("%7d [%s%.1f%%]\n", files[i].index.flag, ratio<10?" ":"", ratio);
			else
				printf("%3d,%03d [%s%.1f%%]\n", files[i].index.flag/1000, files[i].index.flag%1000, ratio<10?" ":"", ratio);
		}
	}
	free(len);
}

//-----------------------------------------------------------------------------
// Parse file
//-----------------------------------------------------------------------------
void ParseFile(const char* _fn, TFileBlock* fb)
{
	FILE* fp = NULL;
	char fn[ARG_LEN_MAX] = {0};
	unsigned int ret;
	int zLevel = 6;
	
	int len = strlen(_fn);
	if (_fn[len-2] == '/')
	{
		zLevel = _fn[len-1] - '0';
		memcpy(fn, _fn, len-2);
	}
	else
		strcpy(fn, _fn);
	
	if ((fp = fopen(fn, "rb")) == NULL)
	{
		printf("File not found! %s\n", fn);
		return;
	}
	fseek(fp, 0, SEEK_END);
	fb->index.oSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fb->oData = (TUint8*)malloc(fb->index.oSize);
	if ((ret=fread(fb->oData, 1, fb->index.oSize, fp)) != fb->index.oSize)
	{
		printf("Read file error! %d != %d\n", ret, fb->index.oSize);
		free(fb->oData);
		fb->oData = NULL;
	}
	fclose(fp);

	/*
	fb->index.zSize = compressBound(fb->index.oSize);
	fb->zData = (TUint8*)malloc(fb->index.zSize);
	ret = compress2(fb->zData, (unsigned long*)&fb->index.zSize, fb->oData, fb->index.oSize, zLevel);

	if (ret)	// SZ_OK==0, Z_OK==0
	{
		printf("Compress `%s' error! %d\n", _fn, ret);
	}
	*/
	TUint outPropsSize = 5;
	TUint8 outProps[5];
	TUint ezSize = fb->index.oSize / 20 * 21 + (1 << 16);
	TUint8* ezData = (TUint8*)malloc(ezSize);
	ret = LzmaCompress(ezData, &ezSize, fb->oData, fb->index.oSize,
		(unsigned char*)&outProps,	//unsigned char *outProps,
		&outPropsSize, // *outPropsSize must be = 5
		5,		//zLevel,	//int level,            // 0 <= level <= 9, default = 5
		DICT_SIZE,	//unsigned dictSize,  // default = (1 << 24)
		3,		//int lc,        // 0 <= lc <= 8, default = 3
		0,		//int lp,        // 0 <= lp <= 4, default = 0
		2,		//int pb,        // 0 <= pb <= 4, default = 2
		32,		//int fb,        // 5 <= fb <= 273, default = 32
		1		//int numThreads // 1 or 2, default = 2
	);
	free(ezData);
	if (ret)
	{
		printf("Compress `%s' error! %d\n", _fn, ret);
	}
	else
	{
		fb->index.flag = ezSize;
	}

	strcpy(fb->fileName, fn);
	fb->index.nHash1 = HashStr(fn, 1);
	fb->index.nHash2 = HashStr(fn, 2);
	
	return;
}

void CleanFileBlock(TFileBlock* fb)
{
	if (fb)
	{
		if (fb->oData) free(fb->oData);
	//	if (fb->zData) free(fb->zData);
	}
}

void PrintUsage()
{
	printf("\n");
	printf("Pak7z.exe v1.02\n");
	printf("ER1C<eric.wangxh@gmail.com>, 2009-08-16.\n");
	printf("\n");
	printf("Usage: pak7z.exe [output.pk3] [list.txt]\n");
	printf("\n");
}

static void *SzAlloc(void *p, size_t size) { p = p; return MyAlloc(size); }
static void SzFree(void *p, void *address) { p = p; MyFree(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

//-----------------------------------------------------------------------------
// main
//-----------------------------------------------------------------------------
#define Z_FNDATA	1

int main(int argc, char** argv)
{
	unsigned int i, oTotal = 0, zTotal = 0, wrote = 0, ezTotal = 0;
	TPk3Header header;
	TFileBlock* files;
	FILE* fp;
	char *pakFile, *listFile;
//	char *oFNData, *zFNData;
//	int oFNSize;//, zFNSize;
	unsigned int oHeaderSize, zHeaderSize;
	TUint8 *oHeader, *zHeader;
	int ret;
	TUint8 *oData, *zData;
	unsigned int outPropsSize = 5;
	TUint8 outProps[5] = {0};

	if (argc<3)
	{
		PrintUsage();
		return -1;
	}

	pakFile = argv[1];
	listFile = argv[2];

	fp = fopen(listFile, "rb");
	if (!fp)
	{
		printf("Open `%s' failed!\n", listFile);
		return -1;
	}

	char c = 0;
	char line[ARG_LEN_MAX] = {0};
	bool commented = false;
	int _argc = 0;
	char** _argv = new char*[ARGC_MAX];
	for (i=0; i<ARGC_MAX; i++)
	{
		_argv[i] = new char[ARG_LEN_MAX];
	}
	i = 0;
	while ((c=getc(fp)) != EOF)
	{
		if (c==0x0D || c==0x0A)
		{
			if (!commented && strlen(line) > 0)
			{
				strcpy(_argv[_argc++], line);
				memset(line, 0, ARG_LEN_MAX);
			}
			commented = false;
			i = 0;
		}
		else if (c == '#')
		{
			commented = true;
		}
		else if (!commented)
		{
			line[i++] = c;
		}
	}
	fclose(fp);	// [list.txt]

	memset(&header, 0, sizeof(header));
	header.pakVersion = 3;
	header.fileNumber = _argc;

	files = (TFileBlock*)malloc(sizeof(TFileBlock)*header.fileNumber);

	InitCryptTable();

	//------------------------------------------------------------------------
	// read files
	oData = new TUint8[ODATA_MAX];
	header.oDataSize = 0;

	for (i=0; i<header.fileNumber; i++)
	{
		memset(&files[i], 0, sizeof(TFileBlock));
		ParseFile(_argv[i], &files[i]);
		if (i==0)
			files[i].index.filePos = 0;
		else
			files[i].index.filePos = files[i-1].index.filePos + files[i-1].index.oSize;
	//	header.fileNamePos = files[i].index.filePos + files[i].index.oSize;
		if (header.oDataSize+files[i].index.oSize >= ODATA_MAX)
		{
			printf("Too many input files! Exceeds %d KB! @%s\n\n", ODATA_MAX/1024, files[i].fileName);
			free(files);
			free(oData);
			return -1;
		}
		memcpy(oData+header.oDataSize, files[i].oData, files[i].index.oSize);
		header.oDataSize += files[i].index.oSize;
		ezTotal += files[i].index.flag;
	}
	oTotal += header.oDataSize;

	PrintAligned(files, header.fileNumber);

	//------------------------------------------------------------------------
	// compress header
	oHeaderSize = sizeof(TPakIndex)*header.fileNumber;
	oHeader = new TUint8[oHeaderSize];
	for (i=0; i<header.fileNumber; i++)
	{
		memcpy(oHeader+i*sizeof(TPakIndex), &files[i].index, sizeof(TPakIndex));
	}

	zHeaderSize = oHeaderSize/20*21 + (1<<16);
	zHeader = new TUint8[zHeaderSize];

	ret = LzmaCompress(zHeader, &zHeaderSize, oHeader, oHeaderSize,
		(unsigned char*)&outProps,	//unsigned char *outProps,
		&outPropsSize, // *outPropsSize must be = 5
		5,		//zLevel,	//int level,            // 0 <= level <= 9, default = 5
		DICT_SIZE,	//unsigned dictSize,  // default = (1 << 24)
		3,		//int lc,        // 0 <= lc <= 8, default = 3
		0,		//int lp,        // 0 <= lp <= 4, default = 0
		2,		//int pb,        // 0 <= pb <= 4, default = 2
		32,		//int fb,        // 5 <= fb <= 273, default = 32
		1		//int numThreads // 1 or 2, default = 2
	);

	memcpy(zHeader+zHeaderSize, outProps, 5);
	zHeaderSize += 5;
	header.zHeaderSize = zHeaderSize;

//	printf("Header: %7d,%03d -> %7d,%03d\n", oHeaderSize, header.zHeaderSize);
	if (oHeaderSize < 1000)
		printf("\n\tHeader: %8d -> ", oHeaderSize);
	else
		printf("\n\tHeader: %4d,%03d -> ", oHeaderSize/1000, oHeaderSize%1000);

	if (header.zHeaderSize < 1000)
		printf("%8d Bytes\n", header.zHeaderSize);
	else
		printf("%4d,%03d Bytes\n", header.zHeaderSize/1000, header.zHeaderSize%1000);

	delete[] oHeader;

	//------------------------------------------------------------------------
	// compress data
	header.zDataSize = header.oDataSize / 20 * 21 + (1 << 16);
	zData = (TUint8*)malloc(header.zDataSize);
	ret = LzmaCompress(zData, &header.zDataSize, oData, header.oDataSize,
		(unsigned char*)&outProps,	//unsigned char *outProps,
		&outPropsSize, // *outPropsSize must be = 5
		5,		//zLevel,	//int level,            // 0 <= level <= 9, default = 5
		DICT_SIZE,	//unsigned dictSize,  // default = (1 << 24)
		3,		//int lc,        // 0 <= lc <= 8, default = 3
		0,		//int lp,        // 0 <= lp <= 4, default = 0
		2,		//int pb,        // 0 <= pb <= 4, default = 2
		32,		//int fb,        // 5 <= fb <= 273, default = 32
		1		//int numThreads // 1 or 2, default = 2
	);

	memcpy(zData+header.zDataSize, outProps, 5);
	header.zDataSize += 5;

//	printf("Data  : %d -> %d\n", header.oDataSize, header.zDataSize);
	if (header.oDataSize < 1000)
		printf("\t  Data: %8d -> ", header.oDataSize);
	else
		printf("\t  Data: %4d,%03d -> ", header.oDataSize/1000, header.oDataSize%1000);

	if (header.oDataSize < 1000)
		printf("%8d Bytes", header.zDataSize);
	else
		printf("%4d,%03d Bytes", header.zDataSize/1000, header.zDataSize%1000);
	printf(" [ESTIMATED: %d,%03d]\n", ezTotal/1000, ezTotal%1000);

	delete[] oData;

	if (ret)
	{
		printf("Compress error! %d\n", ret);
	}

	for (i=0; i<ARGC_MAX; i++)
	{
		delete[] _argv[i];
	}
	delete[] _argv;

	//------------------------------------------------------------------------
	// output .pak file
	fp = fopen(pakFile, "wb");
	if (fp == NULL)
	{
		printf("Write file failed!\n");
		goto _EXIT;
	}

	wrote += fwrite(&header, 1, sizeof(header), fp);
	zTotal += sizeof(header);

	/*
	for (i=0; i<header.fileNumber; i++)
		wrote += fwrite(&files[i].index, 1, sizeof(TPakIndex), fp);
	zTotal += sizeof(TPakIndex)*header.fileNumber;
	printf("Header: %d\n",wrote);
	*/

	wrote += fwrite(zHeader, 1, header.zHeaderSize, fp);
	zTotal += header.zHeaderSize;
	delete[] zHeader;

	/*
	for (i=0; i<header.fileNumber; i++)
	{
		wrote += fwrite(files[i].zData, 1, files[i].index.zSize, fp);
		zTotal += files[i].index.zSize;
	}
	*/
	wrote += fwrite(zData, 1, header.zDataSize, fp);
	zTotal += header.zDataSize;
	delete[] zData;

	for (i=0; i<header.fileNumber; i++)
	{
		unsigned int j;
		for (j=i+1; j<header.fileNumber; j++)
		{
			if (files[i].index.nHash1 == files[j].index.nHash1)
				printf("%d=%d/nHash1: 0x%x, %s - %s\n", i+1,j+1,files[j].index.nHash1, files[i].fileName, files[j].fileName);
			if (files[i].index.nHash2 == files[j].index.nHash2)
				printf("%d=%d/nHash2: 0x%x, %s - %s\n", i+1,j+1,files[j].index.nHash2, files[i].fileName, files[j].fileName);
		}
	}

	/*
	wrote += fwrite(zFNData, 1, header.fnSize, fp);
	zTotal += header.fnSize;

	if (Z_FNDATA)
		free(zFNData);
	*/

	fclose(fp);

	//-
	if (zTotal != wrote)
		printf("\n>>> Pack error! %d wrote: %d\n\n", zTotal, wrote);
	else
	{
		printf("\tOutput: %4d,%03d -> %4d,%03d Bytes [%.1f%%].\n\n", oTotal/1000, oTotal%1000, zTotal/1000, zTotal%1000, zTotal*100.0/oTotal);
		printf(">>>\tPacked: `%s' %.1f KB.\n\n", pakFile, zTotal/1024.0);
	}

_EXIT:
	for (i=0; i<header.fileNumber; i++)
		CleanFileBlock(&files[i]);
	free(files);

	return 0;
}

// end of file

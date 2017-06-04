//不考虑动态内存换出，所以bmp文件不能是高清的否则内存会溢出.2017.1.3 11:05
#include<bitset>
#include<math.h>
#include<string>
#include <iomanip>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include<conio.h>
#include<iostream>
#include <fstream>
#include <opencv2/core/core.hpp>
#include <opencv2/imgproc/imgproc.hpp>
#include <opencv2/highgui/highgui.hpp>
#include<time.h>
#include "cv.h"
#include "highgui.h"
using namespace cv;
using namespace std;
//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密
//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密

//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密
//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密
//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密
//--------------------------------------------------------------加解密//--------------------------------------------------------------加解密
void encrytoFunction();
void decrytoFunction();
int key_length;
typedef std::bitset<64> Block ;
typedef std::bitset<56> Key ;
typedef std::bitset<48> Code ;

typedef std::bitset<32> HBlock ;
typedef std::bitset<28> HKey ;
typedef std::bitset<24> HCode ;

typedef enum { e , d } Method ;

int ip(const Block & block , HBlock & left , HBlock & right) ;
int des_turn(HBlock & left , HBlock & right , const Code & subkey) ;
int exchange(HBlock & left , HBlock & right) ;
int rip(const HBlock & left , const HBlock & right , Block & block) ;
Code getkey(const unsigned int n , const Block & bkey) ;
int des(Block & block , Block & bkey , const Method method) ;

const static unsigned char ip_table[64] = {
	58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 , 60 , 52 , 44 , 36 , 28 , 20 , 12 , 4 ,
	62 , 54 , 46 , 38 , 30 , 22 , 14 , 6 , 64 , 56 , 48 , 40 , 32 , 24 , 16 , 8 ,
	57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 , 59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
	61 , 53 , 45 , 37 , 29 , 21 , 13 , 5 , 63 , 55 , 47 , 39 , 31 , 23 , 15 , 7
} ;

//扩展置换，将数据从32位扩展为48位
static const unsigned char expa_perm[48] = {
	32 , 1 , 2 , 3 , 4 , 5 , 4 , 5 , 6 , 7 , 8 , 9 , 8 , 9 , 10 , 11 ,
	12 , 13 , 12 , 13 , 14 , 15 , 16 , 17 , 16 , 17 , 18 , 19 , 20 , 21 , 20 , 21 ,
	22 , 23 , 24 , 25 , 24 , 25 , 26 , 27 , 28 , 29 , 28 , 29 , 30 , 31 , 32 , 1
} ;

//S盒子代替
const static unsigned char sbox[8][64]={
       	{//S1盒子
	14 , 4 , 13 , 1 , 2 , 15 , 11 , 8 , 3 , 10 , 6 , 12 , 5 , 9 , 0 , 7 ,
       	0 , 15 , 7 , 4 , 14 , 2 , 13 , 1 , 10 , 6 , 12 , 11 , 9 , 5 , 3 , 8 ,
       	4 , 1 , 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5 , 0 ,
       	15 , 12 , 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11 , 3 , 14 , 10 , 0 , 6 , 13
} ,
	{//S2盒子
       	15 , 1 , 8 , 14 , 6 , 11 , 3 , 4 , 9 , 7 , 2 , 13 , 12 , 0 , 5 , 10 ,
       	3 , 13 , 4 , 7 , 15 , 2 , 8 , 14 , 12 , 0 , 1 , 10 , 6 , 9 , 11 , 5 ,
       	0 , 14 , 7 , 11 , 10 , 4 , 13 , 1 , 5 , 8 , 12 , 6 , 9 , 3 , 2 , 15 ,
       	13 , 8 , 10 , 1 , 3 , 15 , 4 , 2 , 11 , 6 , 7 , 12 , 0 , 5 , 14 , 9
} ,
	{//S3盒子
       	10 , 0 , 9 , 14 , 6 , 3 , 15 , 5 , 1 , 13 , 12 , 7 , 11 , 4 , 2 , 8 ,
       	13 , 7 , 0 , 9 , 3 , 4 , 6 , 10 , 2 , 8 , 5 , 14 , 12 , 11 , 15 , 1 ,
       	13 , 6 , 4 , 9 , 8 , 15 , 3 , 0 , 11 , 1 , 2 , 12 , 5 , 10 , 14 , 7 ,
       	1 , 10 , 13 , 0 , 6 , 9 , 8 , 7 , 4 , 15 , 14 , 3 , 11 , 5 , 2 , 12
} ,
	{//S4盒子
       	7 , 13 , 14 , 3 , 0 , 6 , 9 , 10 , 1 , 2 , 8 , 5 , 11 , 12 , 4 , 15 ,
       	13 , 8 , 11 , 5 , 6 , 15 , 0 , 3 , 4 , 7 , 2 , 12 , 1 , 10 , 14 , 9 ,
       	10 , 6 , 9 , 0 , 12 , 11 , 7 , 13 , 15 , 1 , 3 , 14 , 5 , 2 , 8 , 4 ,
       	3 , 15 , 0 , 6 , 10 , 1 , 13 , 8 , 9 , 4 , 5 , 11 , 12 , 7 , 2 , 14
} ,
       	{//S5盒子
	2 , 12 , 4 , 1 , 7 , 10 , 11 , 6 , 8 , 5 , 3 , 15 , 13 , 0 , 14 , 9 ,
       	14 , 11 , 2 , 12 , 4 , 7 , 13 , 1 , 5 , 0 , 15 , 10 , 3 , 9 , 8 , 6 ,
       	4 , 2 , 1 , 11 , 10 , 13 , 7 , 8 , 15 , 9 , 12 , 5 , 6 , 3 , 0 , 14 ,
       	11 , 8 , 12 , 7 , 1 , 14 , 2 , 13 , 6 , 15 , 0 , 9 , 10 , 4 , 5 , 3
} ,
       	{//S6盒子
	12 , 1 , 10 , 15 , 9 , 2 , 6 , 8 , 0 , 13 , 3 , 4 , 14 , 7 , 5 , 11 ,
       	10 , 15 , 4 , 2 , 7 , 12 , 9 , 5 , 6 , 1 , 13 , 14 , 0 , 11 , 3 , 8 ,
       	9 , 14 , 15 , 5 , 2 , 8 , 12 , 3 , 7 , 0 , 4 , 10 , 1 , 13 , 11 , 6 ,
       	4 , 3 , 2 , 12 , 9 , 5 , 15 , 10 , 11 , 14 , 1 , 7 , 6 , 0 , 8 , 13
} ,
	{//S7盒子
       	4 , 11 , 2 , 14 , 15 , 0 , 8 , 13 , 3 , 12 , 9 , 7 , 5 , 10 , 6 , 1 ,
       	13 , 0 , 11 , 7 , 4 , 9 , 1 , 10 , 14 , 3 , 5 , 12 , 2 , 15 , 8 , 6 ,
       	1 , 4 , 11 , 13 , 12 , 3 , 7 , 14 , 10 , 15 , 6 , 8 , 0 , 5 , 9 , 2 ,
       	6 , 11 , 13 , 8 , 1 , 4 , 10 , 7 , 9 , 5 , 0 , 15 , 14 , 2 , 3 , 12
} ,
	{//S8盒子
       	13 , 2 , 8 , 4 , 6 , 15 , 11 , 1 , 10 , 9 , 3 , 14 , 5 , 0 , 12 , 7 ,
       	1 , 15 , 13 , 8 , 10 , 3 , 7 , 4 , 12 , 5 , 6 , 11 , 0 , 14 , 9 , 2 ,
       	7 , 11 , 4 , 1 , 9 , 12 , 14 , 2 , 0 , 6 , 10 , 13 , 15 , 3 , 5 , 8 ,
       	2 , 1 , 14 , 7 , 4 , 10 , 8 , 13 , 15 , 12 , 9 , 0 , 3 , 5 , 6 , 11
}
} ;

//P盒置换
const static unsigned char p_table[32] = {
	16 , 7 , 20 , 21 , 29 , 12 , 28 , 17 , 1 , 15 , 23 , 26 , 5 , 18 , 31 , 10 ,
	2 , 8 , 24 , 14 , 32 , 27 , 3 , 9 , 19 , 13 , 30 , 6 , 22 , 11 , 4 , 25
} ;

//末置换
const static unsigned char ipr_table[64] = {
	40 , 8 , 48 , 16 , 56 , 24 , 64 , 32 , 39 , 7 , 47 , 15 , 55 , 23 , 63 , 31 ,
	38 , 6 , 46 , 14 , 54 , 22 , 62 , 30 , 37 , 5 , 45 , 13 , 53 , 21 , 61 , 29 ,
	36 , 4 , 44 , 12 , 52 , 20 , 60 , 28 , 35 , 3 , 43 , 11 , 51 , 19 , 59 , 27 ,
	34 , 2 , 42 , 10 , 50 , 18 , 58 , 26 , 33 , 1 , 41 , 9 , 49 , 17 , 57 , 25
} ;

//将数据块初始置换为左右两个部分
int ip(const Block & block , HBlock & left , HBlock & right)
{
	for(size_t i = 0 ; i < right.size() ; ++i)
		right[i] = block[ip_table[i] - 1] ;//获取置换后的右半部分
	for(size_t i = 0 ; i < left.size() ; ++i)
		left[i] = block[ip_table[i + left.size()] - 1] ;//获取置换后的左半部分
	return 0 ;
}

//一轮加解密运算，不带交换
int des_turn(HBlock & left , HBlock & right , const Code & subkey)
{
	Code code ;//48位数据块
	HBlock pcode ;//32位数据块
	//将右半部分扩展为48位
	for(size_t i = 0 ; i < code.size() ; ++i)
		code[i] = right[expa_perm[i] - 1] ;//扩展置换
	code ^= subkey ;//与子密钥异或
	//S盒代替
	std::bitset<4> col ;//S盒的列
	std::bitset<2> row ;//S盒的行
	for(size_t i = 0 ; i < 8 ; ++i)
	{//8个盒子
		row[0] = code[6 * i] ;//获取行标
		row[1] = code[6 * i + 5] ;
		col[0] = code[6 * i + 1] ;//获取列标
		col[1] = code[6 * i + 2] ;
		col[2] = code[6 * i + 3] ;
		col[4] = code[6 * i + 4] ;
		std::bitset<4> temp(sbox[i][row.to_ulong() * 16 + col.to_ulong()]) ;
		for(size_t j = 0 ; j < temp.size() ; ++j)
			code[4 * i + j] = temp[j] ;//将32位暂存于48位中
	}
	for(size_t i = 0 ; i < pcode.size() ; ++i)
		pcode[i] = code[p_table[i] - 1] ;//P盒置换
	left ^= pcode ;//异或
	return 0 ;
}

//交换左右两个部分
int exchange(HBlock & left , HBlock & right)
{
	HBlock temp ;
	for(size_t i = 0 ; i < temp.size() ; ++i)
		temp[i] = left[i] ;
	for(size_t i = 0 ; i < left.size() ; ++i)
		left[i] = right[i] ;
	for(size_t i = 0 ; i < right.size() ; ++i)
		right[i] = temp[i] ;
	return 0 ;
}

//将左右两部分数据进行末置换形成一个数据块
int rip(const HBlock & left , const HBlock & right , Block & block)
{
	for(size_t i = 0 ; i < block.size() ; ++i)
	{
		if(ipr_table[i] <= 32)
			block[i] = right[ipr_table[i] - 1] ;//从right部分获取数据
		else
			block[i] = left[ipr_table[i] - 32 - 1] ;//从left部分获取数据
	}
	return 0 ;
}

//密钥置换表，将64位密钥置换压缩置换为56位
const static unsigned char key_table[56] = {
	57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 ,
	58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 ,
	59 , 51 , 43 , 35 , 27 , 19 , 11 , 3 ,
	60 , 52 , 44 , 36 , 63 , 55 , 47 , 39 ,
	31 , 23 , 15 , 7 , 62 , 54 , 46 , 38 ,
	30 , 22 , 14 , 6 , 61 , 53 , 45 , 37 ,
	29 , 21 , 13 , 5 , 28 , 20 , 12 , 4
} ;

//每轮移动的位数
const static unsigned char bit_shift[16] = {
	1 , 1 , 2 , 2 , 2 , 2 , 2 , 2 , 1 , 2 , 2 , 2 , 2 , 2 , 2 , 1
} ;

//压缩置换表，56位密钥压缩位48位密钥
const static unsigned char comp_perm[48] = {
	14 , 17 , 11 , 24 , 1 , 5 , 3 , 28 ,
	15 , 6 , 21 , 10 , 23 , 19 , 12 , 4 ,
	26 , 8 , 16 , 7 , 27 , 20 , 13 , 2 ,
	41 , 52 , 31 , 37 , 47 , 55 , 30 , 40 ,
	51 , 45 , 33 , 48 , 44 , 49 , 39 , 56 ,
	34 , 53 , 46 , 42 , 50 , 36 , 29 , 32
} ;

//获取bkey产生的第n轮子密钥
Code getkey(const unsigned int n , const Block & bkey)
{//n在区间[0,15]之间取值，bkey为64位密钥
	Code result ;//返回值,48位子密钥
	Key key ;//56位密钥
	unsigned int klen = key.size() , rlen = result.size() ;//分别为56和48
	//获取56位密钥
	for(size_t i = 0 ; i < key.size() ; ++i)
		key[i] = bkey[key_table[i] - 1] ;//密钥置换
	for(size_t i = 0 ; i <= n ; ++i)
	{//循环移位
		for(size_t j = 0 ; j < bit_shift[i] ; ++j)
		{
			//将密钥循环位暂存在result中
			result[rlen - bit_shift[i] + j] = key[klen - bit_shift[i] + j] ;
			result[rlen / 2 - bit_shift[i] + j] = key[klen / 2 - bit_shift[i] + j] ;
		}
		key <<= bit_shift[i] ;//移位
		for(size_t j = 0 ; j < bit_shift[i] ; ++j)
		{
			//写回key中
			key[klen / 2 + j] = result[rlen - bit_shift[i] + j] ;
			key[j] = result[rlen / 2 - bit_shift[i] + j] ;
		}
	}
	//压缩置换
	for(size_t i = 0 ; i < result.size() ; ++i)
		result[i] = key[comp_perm[i] - 1] ;
	return result ;
}

//加解密运算
int des(Block & block , Block & bkey , const Method method)
{//block为数据块，bkey为64位密钥
	HBlock left , right ;//左右部分
	ip(block , left , right) ;//初始置换
	switch(method)
	{
		case e://加密
			for(char i = 0 ; i < 16 ; ++i)
			{
				Code key = getkey(i , bkey) ;
				des_turn(left , right , key) ;
				if(i != 15) exchange(left , right) ;
			}
			break ;
		case d://解密
			for(char i = 15 ; i >= 0 ; --i)
			{
				Code key = getkey(i , bkey) ;
				des_turn(left , right , key) ;
				if(i != 0) exchange(left , right) ;
			}
			break ;
		default:
			break ;
	}
	rip(left , right , block) ;//末置换
	return 0 ;
}
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//-----------------------------------------------图像处理//-----------------------------------------------图像处理//-----------------------------------------------图像处理
//以下该模块是完成BMP图像(彩色图像是24bit RGB各8bit)的像素获取，并存在文件名为xiang_su_zhi.txt中
unsigned char *pBmpBuf;//读入图像数据的指针

int bmpWidth;//图像的宽
int bmpHeight;//图像的高
RGBQUAD *pColorTable;//颜色表指针

int biBitCount;//图像类型，每像素位数
int bmpDataSize;
char bmpname_jiami[20];
char bmpname_jiemi[20];
//-------------------------------------------------------------------------------------------
//读图像的位图数据、宽、高、颜色表及每像素位数等数据进内存，存放在相应的全局变量中
bool readBmp(char *bmpName)
{
    FILE *fp=fopen(bmpName,"rb");//二进制读方式打开指定的图像文件

    if(fp==0)
        return 0;

    //跳过位图文件头结构BITMAPFILEHEADER

    fseek(fp, sizeof(BITMAPFILEHEADER),0);

    //定义位图信息头结构变量，读取位图信息头进内存，存放在变量head中

    BITMAPINFOHEADER head;

    fread(&head, sizeof(BITMAPINFOHEADER), 1,fp); //获取图像宽、高、每像素所占位数等信息

    bmpWidth = head.biWidth;

    bmpHeight = head.biHeight;

    biBitCount = head.biBitCount;//定义变量，计算图像每行像素所占的字节数（必须是4的倍数）

    int lineByte=(bmpWidth * biBitCount/8+3)/4*4;//行像素公式

    if(biBitCount==8)
    {

        //申请颜色表所需要的空间，读颜色表进内存

        pColorTable=new RGBQUAD[256];

        fread(pColorTable,sizeof(RGBQUAD),256,fp);

    }

    //申请位图数据所需要的空间，读位图数据进内存
    bmpDataSize=lineByte*bmpHeight;
    pBmpBuf=new unsigned char[lineByte * bmpHeight];

    fread(pBmpBuf,1,lineByte * bmpHeight,fp);

    fclose(fp);//关闭文件

    return 1;//读取文件成功
}

//-----------------------------------------------------------------------------------------
//给定一个图像位图数据、宽、高、颜色表指针及每像素所占的位数等信息,将其写到指定文件中
bool saveBmp(char *bmpName, unsigned char *imgBuf, int width, int height, int biBitCount, RGBQUAD *pColorTable)
{

    //如果位图数据指针为0，则没有数据传入，函数返回

    if(!imgBuf)
        return 0;

    //颜色表大小，以字节为单位，灰度图像颜色表为1024字节，彩色图像颜色表大小为0

    int colorTablesize=0;

    if(biBitCount==8)
        colorTablesize=1024;

    //待存储图像数据每行字节数为4的倍数

    int lineByte=(width * biBitCount/8+3)/4*4;

    //以二进制写的方式打开文件

    FILE *fp=fopen(bmpName,"wb");

    if(fp==0)
        return 0;

    //申请位图文件头结构变量，填写文件头信息

    BITMAPFILEHEADER fileHead;

    fileHead.bfType = 0x4D42;//bmp类型

    //bfSize是图像文件4个组成部分之和

    fileHead.bfSize= sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + colorTablesize + lineByte*height;

    fileHead.bfReserved1 = 0;

    fileHead.bfReserved2 = 0;

    //bfOffBits是图像文件前3个部分所需空间之和

    fileHead.bfOffBits=54+colorTablesize;

    //写文件头进文件

    fwrite(&fileHead, sizeof(BITMAPFILEHEADER),1, fp);

    //申请位图信息头结构变量，填写信息头信息

    BITMAPINFOHEADER head;

    head.biBitCount=biBitCount;

    head.biClrImportant=0;

    head.biClrUsed=0;

    head.biCompression=0;

    head.biHeight=height;

    head.biPlanes=1;

    head.biSize=40;

    head.biSizeImage=lineByte*height;

    head.biWidth=width;

    head.biXPelsPerMeter=0;

    head.biYPelsPerMeter=0;

    //写位图信息头进内存

    fwrite(&head, sizeof(BITMAPINFOHEADER),1, fp);

    //如果灰度图像，有颜色表，写入文件

    if(biBitCount==8)
        fwrite(pColorTable, sizeof(RGBQUAD),256, fp);

    //写位图数据进文件

    fwrite(imgBuf, height*lineByte, 1, fp);

    //关闭文件

    fclose(fp);

    return 1;

}

//----------------------------------------------------------------------------------------
//以下为像素的读取函数和存放
void readIT()
{
    cout<<"请输入图片名称及相关路径信息"<<endl;
    char readPath[20];
    cin>>readPath;
    strcat(bmpname_jiemi,readPath);
     cout<<"开始读取图片信息........................."<<endl;
    //读入指定BMP文件进内存
    readBmp(readPath);
    //输出图像的信息
    cout<<"width="<<bmpWidth<<" height="<<bmpHeight<<" biBitCount="<<biBitCount<<endl;

    //循环变量，图像的坐标

    //每行字节数

    int lineByte=(bmpWidth*biBitCount/8+3)/4*4;

    //循环变量，针对彩色图像，遍历每像素的三个分量

    int m=0,n=0,count_xiang_su=0;

    //将图像左下角1/4部分置成黑色
    char t[15];
    cout<<"请输入保存像素的文件名称"<<endl;
    cin>>t;
    ofstream outfile(t,ios::in|ios::trunc);

    if(biBitCount==8) //有bug 2017.1.5
    {
    //------------------------------------------------------------------------------------
    //以下完成图像的分割成8*8小单元，并把像素值存储到指定文本中。由于BMP图像的像素数据是从
    //左下角：由左往右，由上往下逐行扫描的
        int L1=0;
        int hang=63;
        int lie=0;
        //int L2=0;
        //int fen_ge=8;
        for(int fen_ge_hang=0;fen_ge_hang<8;fen_ge_hang++)//64*64矩阵行循环
        {
            for(int fen_ge_lie=0;fen_ge_lie<8;fen_ge_lie++)//64*64列矩阵循环
            {
            //--------------------------------------------
                for(L1=hang;L1>hang-8;L1--)//8*8矩阵行
                {
                    for(int L2=lie;L2<lie+8;L2++)//8*8矩阵列
                    {
                        m=*(pBmpBuf+L1*lineByte+L2);
                        outfile<<m<<" ";
                        count_xiang_su++;
                        if(count_xiang_su%8==0)//每8*8矩阵读入文本文件
                        {
                            outfile<<endl;
                        }
                    }
                }
            //---------------------------------------------
                hang=63-fen_ge_hang*8;//64*64矩阵行变换
                lie+=8;//64*64矩阵列变换
                    //该一行（64）由8个8*8矩阵的行组成
            }
            hang-=8;//64*64矩阵的列变换
            lie=0;//64*64juzhen
        }
    }

    //double xiang_su[2048];
    //ofstream outfile("xiang_su_zhi.txt",ios::in|ios::trunc);
    if(!outfile)
    {
        cout<<"open error!"<<endl;
        exit(1);
    }
    else if(biBitCount==24)//有bug 2017.1.5
    {//彩色图像
        for(int i=0;i<bmpHeight;i++)
        {
            for(int j=0;j<bmpWidth;j++)
            {
                for(int k=0;k<3;k++)//每像素RGB三个分量分别置0才变成黑色
                {
                    //*(pBmpBuf+i*lineByte+j*3+k)-=40;
                    m=*(pBmpBuf+i*lineByte+j*3+k);
                    outfile<<m<<" ";
                    count_xiang_su++;
                    if(count_xiang_su%8==0)
                    {
                        outfile<<endl;
                    }
                //n++;
                }
                n++;
            }


        }
        cout<<"总的像素个素为:"<<n<<endl;
        cout<<"----------------------------------------------------"<<endl;
    }

    //将图像数据存盘


}


void writeIT()
{
    char writePath[20];//存储
    cout<<"请输入存放图片名称"<<endl;
    cin>>writePath;
    strcat(bmpname_jiami,writePath);
    saveBmp(writePath,pBmpBuf, bmpWidth, bmpHeight, biBitCount, pColorTable);

    //清除缓冲区，pBmpBuf和pColorTable是全局变量，在文件读入时申请的空间

    delete []pBmpBuf;

    if(biBitCount==8)
        delete []pColorTable;
}
void encrytoFunction()
{

    //加密采用ECB模式
    cout<<"加密开始...........................(1min)"<<endl;
    int a[bmpDataSize];
    int cipher[bmpDataSize];
    for(int countt=0;countt<bmpDataSize;countt++)
    {
        a[countt]=pBmpBuf[countt];
    }
    /*for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=a[countt];
    }*/
    //以上测试用：证明2017.1.3 char和int保存二进制数据可以转换
   /* for(int i=0;i<bmpDataSize;i++)
    {
        srand(i);
        swap(a[(i+rand())%bmpDataSize],a[(i+rand())%bmpDataSize]);
    }
    for(int i=0;i<bmpDataSize;i++)
    {
        srand(i*2);
        swap(a[(i+rand()*10)%bmpDataSize],a[(i+rand()*120)%bmpDataSize]);
    }
    for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=a[countt];
    }
*/

    Block stream;
    int k_t=123456;
    cout<<"请输入加密密钥(默认123456)"<<endl;
    cin>>k_t;
    key_length=k_t;
    Block key(k_t);
    for(int x=0;x<bmpDataSize/8;x++)//
    {

    for(int aa=0;aa<8;aa++)
    {
        //cout<<a[x*8+aa]<<endl;
         bitset<8> unit(a[x*8+aa]);
         for(int s=7;s>=0;s--)
         {
             stream[(aa*8+s)%64]=unit[s];  //将8位赋值到64内
         }
    }
    des(stream,key,e);
    for(int aa=0;aa<8;aa++)
    {
         bitset<8> unit;
         for(int s=7;s>=0;s--)
         {
             unit[s]=stream[(aa*8+s)%64];  //将64位拆成8位后转码成像素值
         }
         cipher[x*8+aa]=unit.to_ulong();
    }

    }
    //将密文赋值移动到像素内
     for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=cipher[countt];
    }



    //FILE *temp=fopen("temp","wb");
    //fwrite(&pBmpBuf,1,bmpDataSize,temp);
    //fclose(temp);
}



void decrytoFunction()
{
int a[bmpDataSize];
int cipher[bmpDataSize];
Block stream;
    int k_t=123456;
    cout<<"请输入解密密钥(默认123456)"<<endl;
    cin>>k_t;
    Block key(k_t);

for(int countt=0;countt<bmpDataSize;countt++)
    {
        a[countt]=pBmpBuf[countt];
    }



    for(int x=0;x<bmpDataSize/8;x++)//
    {

    for(int aa=0;aa<8;aa++)
    {
        //cout<<a[x*8+aa]<<endl;
         bitset<8> unit(a[x*8+aa]);
         for(int s=7;s>=0;s--)
         {
             stream[(aa*8+s)%64]=unit[s];  //将8位赋值到64内
         }
    }
    des(stream,key,d);
    for(int aa=0;aa<8;aa++)
    {
         bitset<8> unit;
         for(int s=7;s>=0;s--)
         {
             unit[s]=stream[(aa*8+s)%64];  //将64位拆成8位后转码成像素值
         }
         cipher[x*8+aa]=unit.to_ulong();
    }

    }
    //将密文赋值移动到像素内
     for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=cipher[countt];
    }
}
//--------------------------验证-------------------验证-----------------------------------------------------------------------------------------------------------
//--------------------------验证----------验证-验证-----验证--------------------------------------------------------------------------------------------------------------
//------------------------------验证-验证--------------------验证-----------------------------------------------------------------------------------------------------
int erweizhifangtu( )
{
    cout<<"请输入图片名称"<<endl;
    char name[20];
    cin>>name;
	IplImage* src=cvLoadImage(name);

	IplImage* r_plane  = cvCreateImage( cvGetSize(src), 8, 1 );
	IplImage* g_plane  = cvCreateImage( cvGetSize(src), 8, 1 );
	IplImage* b_plane  = cvCreateImage( cvGetSize(src), 8, 1 );
	IplImage* planes[] = { r_plane, g_plane };

	cvCvtPixToPlane( src, b_plane, g_plane, r_plane, 0 );

	// 生成二维直方图数据结构
	int r_bins =256, b_bins = 256;
	CvHistogram* hist;
	{
		int    hist_size[] = { r_bins, b_bins };
		float  r_ranges[]  = { 0, 255 };          // hue is [0,180]
		float  b_ranges[]  = { 0, 255 };
		float* ranges[]    = { r_ranges,b_ranges };
		hist = cvCreateHist( 2, hist_size, CV_HIST_ARRAY, ranges, 1);
	}
	//计算一张或多张单通道图像image(s) 的直方图
	cvCalcHist( planes, hist, 0, 0 );

	//创建可视化显示直方图内容的图像
	int scale = 2;
	IplImage* hist_img = cvCreateImage(  cvSize( r_bins * scale, b_bins * scale ), 8, 3);
	cvZero( hist_img );

	// 以灰色网格填充直方图
	float max_value = 0;
	cvGetMinMaxHistValue( hist, 0, &max_value, 0, 0 ); //发现最大和最小直方块

	for( int h = 0; h < r_bins; h++ ) {
		for( int s = 0; s < b_bins; s++ ) {
			float bin_val = cvQueryHistValue_2D( hist, h, s ); //查询直方块的值
			int intensity = cvRound( bin_val * 255 / max_value );
			cvRectangle( hist_img,
				cvPoint( h*scale, s*scale ),cvPoint( (h+1)*scale - 1, (s+1)*scale - 1),
				CV_RGB(intensity,intensity,intensity), CV_FILLED);
			}
		}

		cvNamedWindow( "Source", 1 );
		cvShowImage(   "Source", src );

		cvNamedWindow( "H-S Histogram", 1 );
		cvShowImage(   "H-S Histogram", hist_img );

		cvWaitKey(0);
		cvDestroyAllWindows();
    return 0;
}

int huidu_grey_zhifangtu()
{
    cout<<"请输入图片名称"<<endl;
    char name[15];
    cin>>name;
    IplImage * src= cvLoadImage(name);
	IplImage* gray_plane = cvCreateImage(cvGetSize(src),8,1);
	cvCvtColor(src,gray_plane,CV_BGR2GRAY);/////////////

	int hist_size = 256;    //直方图尺寸
	int hist_height = 256;
	float range[] = {0,256};  //灰度级的范围
	float* ranges[]={range};
	//创建一维直方图，统计图像在[0 255]像素的均匀分布
	CvHistogram* gray_hist = cvCreateHist(1,&hist_size,CV_HIST_ARRAY,ranges,1);
	//计算灰度图像的一维直方图
	cvCalcHist(&gray_plane,gray_hist,0,0);
	//归一化直方图
	//cvNormalizeHist(gray_hist,1.0);

	int scale = 2;
	//创建一张一维直方图的“图”，横坐标为灰度级，纵坐标为像素个数（*scale）
	IplImage* hist_image = cvCreateImage(cvSize(hist_size*scale,hist_height),8,3);
	cvZero(hist_image);
	//统计直方图中的最大直方块
	float max_value = 0;
	cvGetMinMaxHistValue(gray_hist, 0,&max_value,0,0);

	//分别将每个直方块的值绘制到图中
	for(int i=0;i<hist_size;i++)
	{
		float bin_val = cvQueryHistValue_1D(gray_hist,i); //像素i的概率
		int intensity = cvRound(bin_val*hist_height/max_value);  //要绘制的高度
		cvRectangle(hist_image,
			cvPoint(i*scale,hist_height-1),
			cvPoint((i+1)*scale - 1, hist_height - intensity),
			CV_RGB(255,255,255));
	}
	cvNamedWindow( "GraySource", 1 );
	cvShowImage("GraySource",gray_plane);
	cvNamedWindow( "H-S Histogram", 1 );
	cvShowImage( "H-S Histogram", hist_image );
	cvWaitKey(0);
	cvDestroyAllWindows();
	return 0;
}

/*void open_image()//图片的路径是自动从调用readIT时候用户输入情况下记录的
{
    IplImage *img=cvLoadImage(bmpname_jiami);
    cvNamedWindow("加密图片");


}*/
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//-----------------------------数据分析函数---------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
void key_space_analysis_keynum()
{
    system("cls");
    cout<<"下面进行【密钥空间分析部分】的加密密钥数量分析"<<endl;
    cout<<"本加密系统采用EBC—DES对数据块进行加密"<<endl;
    cout<<"像素块密钥长度为: ";
    int a=key_length;
    int c=0;
    while(1)
    {
        if(a==0)
            break;
        a=a/10;
        c++;
    }
    cout<<c<<"位";
    cout<<"暴力破解统计次数"<<pow(10,c)<<"次"<<endl;
    cout<<"输入任何键继续"<<endl;
    getch();
}
void key_space_analysis_sensibility()
{
    system("cls");
    cout<<"下面进行【密钥空间分析部分】的密钥灵敏度测试"<<endl;
    cout<<"对加密图进行解密,加密密钥和解密密钥只相差一个数字,先输入正确密钥"<<endl;
    int y_key,wr_key;
    cin>>y_key;
    wr_key=y_key-1;
    cout<<"正确密钥为:"<<y_key<<endl;
    cout<<"相似密钥"<<wr_key<<endl;
    cout<<"下面进行解密验证..."<<endl;
    readIT();
    int a[bmpDataSize];
    int cipher[bmpDataSize];
    Block stream;
    Block key(y_key);
    for(int countt=0;countt<bmpDataSize;countt++)
    {
        a[countt]=pBmpBuf[countt];
    }
    for(int x=0;x<bmpDataSize/8;x++)//
    {

    for(int aa=0;aa<8;aa++)
    {
        //cout<<a[x*8+aa]<<endl;
         bitset<8> unit(a[x*8+aa]);
         for(int s=7;s>=0;s--)
         {
             stream[(aa*8+s)%64]=unit[s];  //将8位赋值到64内
         }
    }
    des(stream,key,d);
    for(int aa=0;aa<8;aa++)
    {
         bitset<8> unit;
         for(int s=7;s>=0;s--)
         {
             unit[s]=stream[(aa*8+s)%64];  //将64位拆成8位后转码成像素值
         }
         cipher[x*8+aa]=unit.to_ulong();
    }

    }
    //将密文赋值移动到像素内
     for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=cipher[countt];
    }
    char writePath[20]="right_bmp.bmp";
saveBmp(writePath,pBmpBuf, bmpWidth, bmpHeight, biBitCount, pColorTable);
//wrong bmp
  for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=a[countt];
    }
    Block keyt(wr_key);
    for(int countt=0;countt<bmpDataSize;countt++)
    {
        a[countt]=pBmpBuf[countt];
    }
    for(int x=0;x<bmpDataSize/8;x++)//
    {

    for(int aa=0;aa<8;aa++)
    {
        //cout<<a[x*8+aa]<<endl;
         bitset<8> unit(a[x*8+aa]);
         for(int s=7;s>=0;s--)
         {
             stream[(aa*8+s)%64]=unit[s];  //将8位赋值到64内
         }
    }
    des(stream,keyt,d);
    for(int aa=0;aa<8;aa++)
    {
         bitset<8> unit;
         for(int s=7;s>=0;s--)
         {
             unit[s]=stream[(aa*8+s)%64];  //将64位拆成8位后转码成像素值
         }
         cipher[x*8+aa]=unit.to_ulong();
    }

    }
    //将密文赋值移动到像素内
     for(int countt=0;countt<bmpDataSize;countt++)
    {
        pBmpBuf[countt]=cipher[countt];
    }
    char writePath1[20]="wrong_bmp.bmp";
saveBmp(writePath1,pBmpBuf, bmpWidth, bmpHeight, biBitCount, pColorTable);
   cout<<"正在打开图片比对"<<endl;
   IplImage *right_bmp=cvLoadImage("right_bmp.bmp");
   IplImage *wrong_bmp=cvLoadImage("wrong_bmp.bmp");
   cvShowImage("正确的解密图片",right_bmp);
   cvShowImage("错误的解密图片",wrong_bmp);
   cvWaitKey(0);
   cvDestroyAllWindows();

}





//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------------------------------------------------------
////////////////////////////功能函数
void choice_1()
{
  readIT();
  encrytoFunction();
  writeIT();
  cout<<"是否显示加载图片,是否显示[y]/[n]"<<endl;
  char a;
  cin>>a;
  switch(a)
  {
      case 'y':{IplImage *img=cvLoadImage(bmpname_jiami);cvShowImage("加密后的图像",img);cvWaitKey(0);}break;
      case 'Y':{IplImage *img=cvLoadImage(bmpname_jiami);cvShowImage("加密后的图像",img);cvWaitKey(0);}break;
      case 'n':break;
      case 'N':break;
      default:break;
  }
}
void choice_2()
{
  readIT();
  decrytoFunction();
  writeIT();
  cout<<"是否显示加载图片,是否显示[y]/[n]"<<endl;
  char a;
  cin>>a;
  switch(a)
  {
      case 'y':{IplImage *img=cvLoadImage(bmpname_jiami);cvShowImage("解密后的图像",img);cvWaitKey(0);}break;
      case 'Y':{IplImage *img=cvLoadImage(bmpname_jiami);cvShowImage("解密后的图像",img);cvWaitKey(0);}break;
      case 'n':break;
      case 'N':break;
      default:break;
  }
}
void choice_3()
{
  cout<<"密钥空间分析:"<<endl;
  cout<<"【1】加密密钥数量分析"<<endl;
  cout<<"【2】密钥灵敏度测试"<<endl;
  int choice;
  cin>>choice;
  switch(choice)
  {
      case 1:key_space_analysis_keynum();break;
      case 2:key_space_analysis_sensibility();break;
      default:break;
  }

}
void choice_4()
{
   cout<<"请选择相关性分析方式"<<endl;
   cout<<"【1】RGB二维分布图"<<endl;
   int choice;
   cin>>choice;
   switch(choice)
   {
       case 1:erweizhifangtu();
       default:cout<<"选择错误"<<endl;break;
   }
}
void choice_5()
{
   cout<<"请选择统计显示方式"<<endl;
   cout<<"【1】灰度直方图统计"<<endl;
   int choice;
   cin>>choice;
   switch(choice)
   {
       case 1:huidu_grey_zhifangtu();break;
       default:cout<<"选择错误"<<endl;break;
   }
}
void choice_6()
{
    readIT();
}
////////////////////////////



int main()
{
    int choice;
    while(1)
    {
        system("cls");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_INTENSITY|FOREGROUND_RED|FOREGROUND_GREEN);
    cout<<"*********欢迎使用图像加密系统cmd控制台版*********"<<endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_INTENSITY|FOREGROUND_GREEN|FOREGROUND_BLUE);
    cout<<"【1】加密图片"<<endl;
    cout<<"【2】解密图片"<<endl;
    cout<<"【3】密钥空间分析"<<endl;
    cout<<"【4】相关性分析"<<endl;
    cout<<"【5】统计分析"<<endl;
    cout<<"【6】获取像素信息"<<endl;
    cout<<"【7】退出"<<endl;
    cout<<"等待用户选择..."<<endl;
    cin>>choice;
    switch(choice)
    {
        case 1:choice_1();break;
        case 2:choice_2();break;
        case 3:choice_3();break;
        case 4:choice_4();break;
        case 5:choice_5();break;
        case 6:choice_6();break;
        case 7:exit(1);break;
        default:break;
    }
    }
   SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_INTENSITY|FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);//设置三色相加
    return 0;
}





#include<stdio.h>
#include<string.h>
#include<memory.h>
#include<limits.h>
#define MAX_32BIT_INT 2147483647


#define ADJUST_INDICES(start, end, len)     \
    if (end > len)                          \
        end = len;                          \
    else if (end < 0) {                     \
        end += len;                         \
        if (end < 0)                        \
        end = 0;                            \
    }                                       \
    if (start < 0) {                        \
        start += len;                       \ 
        if (start < 0)                      \
        start = 0;                          \
    }


/*  因为类型可以为任意，所以形参应为void * 
 *  相等则返回0，否则不为0 */  
int my_memcmp(const void *s1,const void *s2,size_t count)  
{  
    int res = 0;  
    const unsigned char *p1 =(const unsigned char *)s1;//注意是unsigned char *  
    const unsigned char *p2 =(const unsigned char *)s2;   
    for(p1 ,p2;count > 0;p1++,p2++,count--)  
        if((res =*p1 - *p2) != 0)   //不相当则结束比较  
            break;  
    return res;  
}  


//匹配函数：endswith与startwith的内部调用函数
int _string_tailmatch(const char *self, const char* substr, int start, int end, int direction)
{
	int selflen = strlen(self);
	int slen = strlen(substr);
		
	const char* str = self;
	const char* sub = substr;

	//对输入的范围进行校准
	ADJUST_INDICES(start, end, selflen);

	//字符串头部匹配（即startswith）
	if (direction < 0)
	{
		if (start + slen>selflen)
			return 0;
	}
	//字符串尾部匹配（即endswith）
	else
	{
		if (end - start<slen || start>selflen)
		    return 0;
		if (end - slen > start)
			start = end - slen;
	}
	if (end - start >= slen)
		//mcmcmp函数用于比较buf1与buf2的前n个字节
		return !my_memcmp(str + start, sub, slen);
	return 0;
		
}


int startswith(const char* str, const char* suffix, int start, int end)
{
    //调用＿string＿tailmatch函数，参数-1表示字符串头部匹配
	int result = _string_tailmatch(str, suffix, start, end, -1);
	return result;
}

int endswith(const char* str, const char* suffix,  int start, int end)
{
    //调用＿string＿tailmatch函数，参数+1表示字符串尾部匹配
	int result = _string_tailmatch(str, suffix, start, end, +1);
	return result;
}

int main()
{
    char* str = "GET /new/client.php?m=iframe&a=getGuestID HTTP/1.1\nHost: 53kf1.artiz.com.cn\nConnection: keep-alive\n";

    char* temp1 = "GET";
    char* temp2 = "\n";
    int length=strlen(str);
    int count=0; 
    int flag;

    char szfiled[132];

    for(int i=0;i<length;i++)
        if(startswith(str,temp1,i,MAX_32BIT_INT))
        {
            memset(szfiled, 0, sizeof(szfiled));
            flag=0;
            for(int j=i;j<length && flag==0;j++)
                if(startswith(str,temp2,j,MAX_32BIT_INT))
                {   
                    count++;
                    memcpy(szfiled, str+i, j-i);// 从第 11 个字符(r)开始复制，连续复制 6 个字符(runoob)

                    szfiled[132]='\0';
                    printf("string is %s\n",szfiled);
                    flag=1;
                    length=strlen(str);
                }
        }
            
	printf("count = %d\n",count);

}
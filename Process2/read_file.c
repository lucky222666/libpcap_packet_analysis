#include <stdlib.h>
#include<stdio.h>
#include<string.h>
#include<stdio.h>
#include<string.h>
#include<mysql.h> 
#include <dirent.h>  
#include <sys/stat.h>  
#include <unistd.h>  
#include <sys/types.h>
#define MAX_32BIT_INT 2147483647
#define SNAP_LEN 1700	
#define MAX_SEG_LEN 1000
#define MAX_PATH_LEN 500


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

//declare variables
DIR *pDir ;  
struct dirent    *ent  ;  
int  i=0  ;  
char filepath[MAX_PATH_LEN];

//需要获取的字段
char buffer[1500];
char *KeyWord1="GET";
char *KeyWord2="Host";
char *KeyWord3="Referer";

char* temp = "\n";
int length;
int flag;
char szfiled1[MAX_SEG_LEN];
char szfiled2[MAX_SEG_LEN];
char szfiled3[MAX_SEG_LEN];
    
//数据库的长链接
MYSQL conn;    
int res;
char insert_query[SNAP_LEN]="";

//打开的文件
FILE * input;

//declare function
int my_memcmp(const void *s1,const void *s2,size_t count);
int _string_tailmatch(const char *self, const char* substr, int start, int end, int direction);
int startswith(const char* str, const char* suffix, int start, int end);
int endswith(const char* str, const char* suffix,  int start, int end);
void read_each_file(char *path,char *filename);


int main(){  
    //数据库的长连接
    mysql_init(&conn);    //初始化连接句柄
    if (mysql_real_connect(&conn, "localhost", "root", "", "Capture", 0, NULL, 0))
	{
	    printf("connect mysql successful\n");   
    }
    //数据库连接失败
	else 
    {
        fprintf(stderr, "Connection failed or it is not DNS packet\n");
        if (mysql_errno(&conn)) {
        fprintf(stderr, "Connection error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
        return 1;
        }
    }

    char *path="/home/lucky222/Mid-term-Professional-Practice/Process1/HTTP_REQUEST/";
    if(chdir(path)!=0)
	{
		printf("chdir error");
		exit(1);
	}
    pDir=opendir(path);  

    while((ent=readdir(pDir))!=NULL)  
    {  
  
        if(ent->d_type & DT_DIR)  
        {  
  
            if(strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0)  
                continue;  
            printf("This is still a directory,need further traversal.\n");   
        }  
        else
        {
            //printf("%s\n", ent->d_name);
            //读取文件内容
            read_each_file(path,ent->d_name);
        }
    } 
    //数据连接关闭 
    mysql_close(&conn);
    
    return 0;
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

void read_each_file(char *path,char *filename)
{
    input = fopen(filename,"r");

    if(input == NULL){
        printf("无法打开文件\n");
        exit(0);
    }
    
    while(fread(buffer,1500,1,input))
    {  

        buffer[strlen(buffer) -1] = '\0';
        length=strlen(buffer);
        if((strstr(buffer, KeyWord1)!=NULL) && (strstr(buffer, KeyWord2)!=NULL) && (strstr(buffer, KeyWord3)!=NULL))
        {
        //检测GET字段
        for(int i=0;i<length;i++)
            if(startswith(buffer,KeyWord1,i,MAX_32BIT_INT))
            {
                memset(szfiled1, 0, sizeof(szfiled1));
                flag=0;
                for(int j=i;j<length && flag==0;j++)
                    if(startswith(buffer,temp,j,MAX_32BIT_INT))
                    {   
                        memcpy(szfiled1, buffer+i, j-i);

                        szfiled1[MAX_SEG_LEN]='\0';
                        //printf("string is %s\n",szfiled);   
                        flag=1;
                        length=strlen(buffer);
                    }
            }

        //检测Host字段
        for(int i=0;i<length;i++)
            if(startswith(buffer,KeyWord2,i,MAX_32BIT_INT))
            {
                memset(szfiled2, 0, sizeof(szfiled2));
                flag=0;
                for(int j=i;j<length && flag==0;j++)
                    if(startswith(buffer,temp,j,MAX_32BIT_INT))
                    {   
                        memcpy(szfiled2, buffer+i, j-i);

                        szfiled2[MAX_SEG_LEN]='\0';
                        //printf("string is %s\n",szfiled);
                        flag=1;
                        length=strlen(buffer);
                    }
            }

        //检测URL字段
        for(int i=0;i<length;i++)
            if(startswith(buffer,KeyWord3,i,MAX_32BIT_INT))
            {
                memset(szfiled3, 0, sizeof(szfiled3));
                flag=0;
                for(int j=i;j<length && flag==0;j++)
                    if(startswith(buffer,temp,j,MAX_32BIT_INT))
                    {   
                        memcpy(szfiled3, buffer+i, j-i);

                        szfiled3[MAX_SEG_LEN]='\0';
                        //printf("string is %s\n",szfiled);
                        flag=1;
                        length=strlen(buffer);
                    }
            }
        
        //数据入库
        memset(filepath,0,sizeof(filepath));
        sprintf(filepath,"%s%s",path,filename);

        memset(insert_query, 0, sizeof(insert_query));
        sprintf(insert_query, "insert into http_analysis values('%d','%s','%s','%s','%s')",atoi(filename), szfiled1,szfiled2,szfiled3,filepath);
                        
        insert_query[strlen(insert_query)]='\0';
        //printf("SQL语句: %s\n", insert_query);
        res = mysql_query(&conn, insert_query);                
        if (!res) {
            printf("Insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
        }                
        else {
            fprintf(stderr, "Insert error %d: %s\n", mysql_errno(&conn),mysql_error(&conn));
        }  

        }    
    }
    fclose(input);    
}
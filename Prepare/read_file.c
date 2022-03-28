
#include <stdlib.h>
#include<stdio.h>

 
int main(){
    FILE * input = fopen("test.txt","rb");
 
    if(input == NULL){
        printf("无法打开文件");
        exit(0);
    }
    
    char buffer[1500];
    int validCount;//实际读取多少数据项
    while((validCount = fread(buffer,sizeof(buffer),5,input))!=0){
        for(int i=0;i<validCount;++i){
            printf("%s\n",buffer);
        }
    }
 
    fclose(input);
    return 0;
}
